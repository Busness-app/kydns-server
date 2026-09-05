package backup

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/Busness-app/ky-primitives/capsule"
	"github.com/Busness-app/ky-primitives/keyfile"
	"github.com/Busness-app/ky-primitives/recoveryclient"
	"github.com/Busness-app/kydns-server/internal/config"
	"github.com/Busness-app/kydns-server/internal/store"
	"gopkg.in/yaml.v3"
)

// Drill serializes both HTTP entry points. Scratch stays under DataDir and is
// created and removed by the library; the product never holds a suite private key.
func (s *Service) Drill(ctx context.Context) (*recoveryclient.DrillResult, error) {
	s.drillMu.Lock()
	defer s.drillMu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p, err := s.Collect()
	if err != nil {
		return nil, err
	}
	return recoveryclient.Drill(ctx, s.Cfg.DataDir, p, drillChecks)
}

// drillChecks reads only the opened manifest and extracted files. A malformed
// recipe fails before any member is read, rather than disabling a required check.
func drillChecks(dir string, opened capsule.Manifest) []recoveryclient.Check {
	var checks []recoveryclient.Check
	check := func(name string, err error) bool {
		c := recoveryclient.Check{Name: name, Passed: err == nil}
		if err != nil {
			c.Message = recoveryclient.AuditSafe(err.Error())
		}
		checks = append(checks, c)
		return c.Passed
	}
	required, sqlitePaths, err := drillRecipe(opened)
	if !check("verification recipe", err) {
		return checks
	}
	// Validate every path before any reads, including symlinked parent directories.
	for _, name := range required {
		if err := regularDrillFile(dir, name); err != nil {
			check("required files", fmt.Errorf("%s: %w", name, err))
			return checks
		}
	}
	check("required files", nil)
	for _, name := range sqlitePaths {
		if !check("sqlite integrity", store.VerifySnapshot(filepath.Join(dir, name))) {
			return checks
		}
	}
	key, err := keyfile.Load(filepath.Join(dir, "data/backup_key"), 32)
	if !check("backup key", err) {
		return checks
	}
	raw, err := os.ReadFile(filepath.Join(dir, "config/kydns.yaml"))
	if err == nil {
		var cfg config.Config
		if yaml.Unmarshal(raw, &cfg) != nil {
			err = errors.New("restored configuration is not valid YAML")
		} else if cfg.DataDir == "" {
			err = errors.New("restored configuration requires data_dir")
		} else {
			for _, addr := range []string{cfg.DNS.Listen, cfg.Admin.Listen} {
				if _, _, e := net.SplitHostPort(addr); e != nil {
					err = errors.New("restored configuration requires valid DNS and admin listeners")
				}
			}
		}
	}
	check("configuration", err)
	if slices.Contains(required, "data/node_key") {
		raw, err := os.ReadFile(filepath.Join(dir, "data/node_key"))
		if err == nil && len(raw) != ed25519.SeedSize {
			err = errors.New("node_key must contain an Ed25519 seed")
		}
		check("node identity", err)
	}
	check("recovery pairing", drillPairing(filepath.Join(dir, "data"), key, slices.Contains(required, "data/recovery.pub")))
	return checks
}

func drillRecipe(m capsule.Manifest) (required, sqlitePaths []string, err error) {
	if m.ServiceName != ServiceName {
		return nil, nil, errors.New("opened capsule does not name KyDNS")
	}
	r, ok := m.VerificationRecipe.(map[string]any)
	if !ok || r["check_sqlite_integrity"] != true {
		return nil, nil, errors.New("recipe must require SQLite integrity checks")
	}
	members := make(map[string]bool, len(m.Files))
	for _, f := range m.Files {
		if !validDrillPath(f.Path) || members[f.Path] {
			return nil, nil, errors.New("invalid or duplicate manifest path")
		}
		members[f.Path] = true
	}
	list := func(field string) ([]string, error) {
		values, ok := r[field].([]any)
		if !ok || len(values) == 0 {
			return nil, fmt.Errorf("recipe %s must be a nonempty string list", field)
		}
		out := make([]string, 0, len(values))
		for _, v := range values {
			name, ok := v.(string)
			if !ok || !validDrillPath(name) || !members[name] || slices.Contains(out, name) {
				return nil, fmt.Errorf("recipe %s contains an invalid, duplicate, or unlisted path", field)
			}
			out = append(out, name)
		}
		return out, nil
	}
	if required, err = list("required_files"); err != nil {
		return nil, nil, err
	}
	if sqlitePaths, err = list("sqlite_paths"); err != nil {
		return nil, nil, err
	}
	mandatory := []string{"data/kydns.db", "data/backup_key", "config/kydns.yaml"}
	for _, name := range []string{"data/node_key", "data/recovery.pub"} {
		if members[name] {
			mandatory = append(mandatory, name)
		}
	}
	for _, name := range append(mandatory, sqlitePaths...) {
		if !slices.Contains(required, name) {
			return nil, nil, errors.New("recipe omits a required KyDNS member")
		}
	}
	if !slices.Contains(sqlitePaths, "data/kydns.db") {
		return nil, nil, errors.New("recipe omits the KyDNS database integrity check")
	}
	return required, sqlitePaths, nil
}

func validDrillPath(name string) bool {
	return name != "." && fs.ValidPath(name) && !strings.ContainsAny(name, "\\:\x00")
}

func regularDrillFile(dir, name string) error {
	parts := strings.Split(name, "/")
	for i, part := range parts {
		dir = filepath.Join(dir, part)
		info, err := os.Lstat(dir)
		if err != nil {
			return err
		}
		if (i < len(parts)-1 && !info.IsDir()) || (i == len(parts)-1 && !info.Mode().IsRegular()) {
			return errors.New("required member must be a regular file inside the sandbox")
		}
	}
	return nil
}

func drillPairing(dataDir string, key []byte, hasPublicKey bool) error {
	st, err := store.OpenSnapshot(filepath.Join(dataDir, "kydns.db"))
	if err != nil {
		return errors.New("cannot read restored pairing settings")
	}
	defer st.Close()
	settings := settingsAdapter{st}
	// Detect partial pairings as well as missing keys; HasPairing alone would
	// silently skip a row lost from the restored database.
	present := func(k string) (bool, error) {
		_, err := settings.Get(k)
		if errors.Is(err, recoveryclient.ErrNotFound) {
			return false, nil
		}
		return err == nil, err
	}
	pinned, err := present(settingKeyID)
	if err != nil {
		return errors.New("cannot read restored key pin")
	}
	if pinned && !hasPublicKey {
		return errors.New("restored pin requires recovery.pub in the manifest")
	}
	if pinned || hasPublicKey {
		k, err := recoveryclient.LoadRecoveryKey(dataDir, settings)
		if err != nil || k.Threshold < 2 || k.TotalShares < k.Threshold || k.TotalShares > 255 {
			return errors.New("restored recovery key or topology is missing, malformed, or does not match its pin")
		}
	}
	u, uerr := present(settingURL)
	t, terr := present("kyrecovery_token_enc")
	if uerr != nil || terr != nil {
		return errors.New("cannot read restored pairing")
	}
	if !u && !t {
		return nil
	}
	sealer, err := recoveryclient.NewAESGCMSealer(key, tokenLabel)
	if err != nil {
		return errors.New("invalid restored backup key")
	}
	p, err := recoveryclient.LoadPairing(dataDir, settings, sealer)
	if err != nil || strings.TrimSpace(p.Token) == "" {
		return errors.New("restored pairing cannot be opened with the restored key")
	}
	return nil
}
