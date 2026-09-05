// Package backup is KyDNS's adapter over ky-primitives/recoveryclient: what to seal, the
// KyDNS drill checks, and one Service the routes, scheduler and CLI share. Pairing,
// key pinning, delivery, schedule and restore live in the library.
package backup

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/Busness-app/ky-primitives/capsule"
	"github.com/Busness-app/ky-primitives/keyfile"
	"github.com/Busness-app/ky-primitives/recoveryclient"
	"github.com/Busness-app/kydns-server/internal/config"
	"github.com/Busness-app/kydns-server/internal/store"
	"gopkg.in/yaml.v3"
)

const (
	ServiceName = "KyDNS"
	keyFile     = "backup_key"
	tokenLabel  = "KyDNS:kyrecovery_token"
	// settingKeyID is the library's pin row. It documents the key but exports no constant.
	settingKeyID = "kyrecovery_key_id"
	settingURL   = "kyrecovery_url"
)

// Service is everything a route, the scheduler and the CLI need. Built once in app.Serve.
type Service struct {
	Cfg     *config.Config
	Store   *store.Store
	Client  *recoveryclient.Client
	Version string
	sealer  recoveryclient.Sealer
}

func New(cfg *config.Config, st *store.Store, version string) (*Service, error) {
	key, err := keyfile.LoadOrCreate(filepath.Join(cfg.DataDir, keyFile), 32)
	if err != nil {
		return nil, err
	}
	sealer, err := recoveryclient.NewAESGCMSealer(key, tokenLabel)
	if err != nil {
		return nil, err
	}
	return &Service{Cfg: cfg, Store: st, Version: version,
		Client: recoveryclient.NewClient(recoveryclient.Options{AllowPrivate: cfg.BackupAllowPrivateRecovery}),
		sealer: sealer}, nil
}

func (s *Service) Sealer() recoveryclient.Sealer { return s.sealer }

// settingsAdapter maps the store's node-local settings onto the library's interface.
type settingsAdapter struct{ st *store.Store }

func (a settingsAdapter) Get(k string) (string, error) {
	v, err := a.st.GetLocalSetting(k)
	if errors.Is(err, store.ErrNotFound) {
		return "", recoveryclient.ErrNotFound
	}
	return v, err
}
func (a settingsAdapter) Set(k, v string) error { return a.st.SetLocalSetting(k, v) }
func (a settingsAdapter) Delete(k string) error { return a.st.DeleteLocalSetting(k) }

func (s *Service) Settings() recoveryclient.Settings { return settingsAdapter{s.Store} }

func (s *Service) runConfig() recoveryclient.RunConfig {
	return recoveryclient.RunConfig{DataDir: s.Cfg.DataDir, AppName: ServiceName, AppVersion: s.Version,
		BackupDir: s.Cfg.BackupDir, Keep: s.Cfg.BackupKeep, Sealer: s.sealer}
}

// Collect is what a KyDNS capsule carries. Missing required members fail closed.
func (s *Service) Collect() (recoveryclient.Payload, error) {
	tmp, err := os.MkdirTemp(s.Cfg.DataDir, ".backup-*")
	if err != nil {
		return recoveryclient.Payload{}, err
	}
	defer os.RemoveAll(tmp)
	dbPath := filepath.Join(tmp, "kydns.db")
	if err := s.Store.SnapshotTo(dbPath); err != nil {
		return recoveryclient.Payload{}, err
	}
	db, err := os.ReadFile(dbPath)
	if err != nil {
		return recoveryclient.Payload{}, err
	}
	manifest, err := yaml.Marshal(map[string]any{"data_dir": s.Cfg.DataDir,
		"dns": map[string]string{"listen": s.Cfg.DNS.Listen}, "admin": map[string]string{"listen": s.Cfg.Admin.Listen}})
	if err != nil {
		return recoveryclient.Payload{}, err
	}
	backupKey, err := os.ReadFile(filepath.Join(s.Cfg.DataDir, keyFile))
	if err != nil {
		return recoveryclient.Payload{}, fmt.Errorf("required backup member %s: %w", keyFile, err)
	}
	files := []recoveryclient.File{
		{Path: "data/kydns.db", Data: db, Mode: 0600},
		{Path: "data/" + keyFile, Data: backupKey, Mode: 0600},
		{Path: "config/kydns.yaml", Data: manifest, Mode: 0600},
	}
	required := []string{"data/kydns.db", "data/" + keyFile, "config/kydns.yaml"}
	// node_key and recovery.pub are carried when they exist, and are then required on the
	// way back: a restored node with the pin row but no key file cannot seal its next backup.
	for _, m := range []struct{ path, src string }{
		{"data/node_key", filepath.Join(s.Cfg.DataDir, "node_key")},
		{"data/recovery.pub", recoveryclient.RecoveryKeyPath(s.Cfg.DataDir)},
	} {
		b, err := os.ReadFile(m.src)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return recoveryclient.Payload{}, err
		}
		files = append(files, recoveryclient.File{Path: m.path, Data: b, Mode: 0600})
		required = append(required, m.path)
	}
	return recoveryclient.Payload{ServiceName: ServiceName, AppVersion: s.Version, Files: files,
		Dependencies:       map[string]any{"ports": []string{s.Cfg.DNS.Listen, s.Cfg.Admin.Listen}},
		VerificationRecipe: map[string]any{"check_sqlite_integrity": true, "sqlite_paths": []string{"data/kydns.db"}, "required_files": required},
	}, nil
}

func (s *Service) Run(ctx context.Context) (recoveryclient.Result, error) {
	return recoveryclient.Run(ctx, s.runConfig(), s.Settings(), s.Collect, s.Client)
}

// Export seals to the pinned key and hands the bytes back without delivering them.
func (s *Service) Export() ([]byte, capsule.Manifest, error) {
	key, err := recoveryclient.LoadRecoveryKey(s.Cfg.DataDir, s.Settings())
	if err != nil {
		return nil, capsule.Manifest{}, err
	}
	p, err := s.Collect()
	if err != nil {
		return nil, capsule.Manifest{}, err
	}
	return recoveryclient.Seal(p, key)
}

// Drill scratch space lives under DataDir: the decrypted payload never lands in the
// system temp directory.
func (s *Service) Drill(ctx context.Context) (*recoveryclient.DrillResult, error) {
	p, err := s.Collect()
	if err != nil {
		return nil, err
	}
	return recoveryclient.Drill(ctx, s.Cfg.DataDir, p, func(dir string) []recoveryclient.Check {
		missing := ""
		for _, f := range p.Files {
			if _, err := os.Stat(filepath.Join(dir, f.Path)); err != nil {
				missing = f.Path
			}
		}
		checks := []recoveryclient.Check{{Name: "required files", Passed: missing == "", Message: missing}}
		db, err := store.Open(filepath.Join(dir, "data", "kydns.db"))
		if err == nil {
			defer db.Close()
			err = db.IntegrityCheck()
		}
		detail := ""
		if err != nil {
			detail = recoveryclient.AuditSafe(err.Error())
		}
		return append(checks, recoveryclient.Check{Name: "sqlite integrity", Passed: err == nil, Message: detail})
	})
}

func (s *Service) Pair(ctx context.Context, url, code string) (recoveryclient.RecoveryKey, error) {
	res, err := s.Client.ClaimPairing(ctx, url, code, ServiceName, ServiceName)
	if err != nil {
		return recoveryclient.RecoveryKey{}, err
	}
	if err := recoveryclient.StoreRecoveryKey(s.Cfg.DataDir, s.Settings(), res.Key); err != nil {
		return res.Key, err
	}
	return res.Key, recoveryclient.StorePairing(s.Settings(), s.sealer, url, res.APIToken)
}

func (s *Service) PinKey(publicKeyB64 string, k, n int) (recoveryclient.RecoveryKey, error) {
	key, err := recoveryclient.ParsePinRequest(publicKeyB64, k, n)
	if err != nil {
		return recoveryclient.RecoveryKey{}, err
	}
	return key, recoveryclient.StoreRecoveryKey(s.Cfg.DataDir, s.Settings(), key)
}

func (s *Service) Unpair() error { return recoveryclient.ClearPairing(s.Settings()) }

// SetSchedule stores whole seconds and reads the stored value back, so the audit row
// and the response report what the scheduler will actually use.
func (s *Service) SetSchedule(sec int64) (time.Duration, error) {
	if err := recoveryclient.SetInterval(s.Settings(), sec); err != nil {
		return 0, err
	}
	return recoveryclient.Interval(s.Cfg.BackupDepositInterval, s.Settings())
}

type Status struct {
	KeyPinned      bool                       `json:"key_pinned"`
	RecoveryKeyID  string                     `json:"recovery_key_id,omitempty"`
	Threshold      int                        `json:"threshold,omitempty"`
	TotalShares    int                        `json:"total_shares,omitempty"`
	KeyPinMissing  bool                       `json:"key_pin_missing"`
	Paired         bool                       `json:"paired"`
	RecoveryURL    string                     `json:"recovery_url,omitempty"`
	AllowPrivate   bool                       `json:"allow_private_recovery"`
	LastDeposit    *recoveryclient.Receipt    `json:"last_deposit,omitempty"`
	LocalDir       string                     `json:"local_dir,omitempty"`
	LocalKeep      int                        `json:"local_keep,omitempty"`
	LocalCopies    []recoveryclient.LocalCopy `json:"local_copies"`
	IntervalSec    int64                      `json:"interval_sec"`
	NextRun        *time.Time                 `json:"next_run,omitempty"`
	HasDestination bool                       `json:"has_destination"`
}

func (s *Service) Status() (Status, error) {
	st := Status{AllowPrivate: s.Cfg.BackupAllowPrivateRecovery, LocalDir: s.Cfg.BackupDir, LocalKeep: s.Cfg.BackupKeep, LocalCopies: []recoveryclient.LocalCopy{}}
	key, err := recoveryclient.LoadRecoveryKey(s.Cfg.DataDir, s.Settings())
	switch {
	case err == nil:
		st.KeyPinned, st.RecoveryKeyID, st.Threshold, st.TotalShares = true, key.Public.ID(), key.Threshold, key.TotalShares
	case errors.Is(err, recoveryclient.ErrKeyPinMissing), errors.Is(err, recoveryclient.ErrKeyMismatch):
		st.KeyPinned, st.KeyPinMissing = true, true
	case errors.Is(err, recoveryclient.ErrNotPaired):
		// The library reports a missing recovery.pub as ErrNotPaired. A pin row without a
		// key file is a stopped backup, not an unconfigured one, so say which it is.
		pinned, perr := s.Settings().Get(settingKeyID)
		if perr != nil && !errors.Is(perr, recoveryclient.ErrNotFound) {
			return st, perr
		}
		if perr == nil && pinned != "" {
			st.KeyPinned, st.KeyPinMissing = true, true
		}
	default:
		return st, err
	}
	st.Paired = recoveryclient.HasPairing(s.Settings())
	if st.Paired {
		if u, err := s.Settings().Get(settingURL); err == nil {
			st.RecoveryURL = u
		}
	}
	if r, ok, err := recoveryclient.LastDeposit(s.Settings()); err != nil {
		return st, err
	} else if ok {
		st.LastDeposit = &r
	}
	if s.Cfg.BackupDir != "" {
		copies, err := recoveryclient.ListLocalCopies(s.Cfg.BackupDir, ServiceName)
		if err != nil {
			return st, err
		}
		st.LocalCopies = copies
	}
	interval, err := recoveryclient.Interval(s.Cfg.BackupDepositInterval, s.Settings())
	if err != nil {
		return st, err
	}
	st.IntervalSec = int64(interval / time.Second)
	if next, on, err := recoveryclient.NextRun(s.Cfg.BackupDepositInterval, s.Settings()); err != nil {
		return st, err
	} else if on {
		st.NextRun = &next
	}
	st.HasDestination = st.Paired || s.Cfg.BackupDir != ""
	return st, nil
}
