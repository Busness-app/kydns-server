// Package backup owns KyDNS disaster-recovery collection, sealing, and deposits.
package backup

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/Busness-app/ky-primitives/capsule"
	"github.com/Busness-app/ky-primitives/keyfile"
	"github.com/Busness-app/ky-primitives/recoverykey"
	"github.com/Busness-app/kydns-server/internal/config"
	"github.com/Busness-app/kydns-server/internal/store"
	"gopkg.in/yaml.v3"
)

const (
	serviceName      = "KyDNS"
	keyFile          = "backup_key"
	publicKeyFile    = "recovery.pub"
	settingURL       = "kyrecovery_url"
	settingToken     = "kyrecovery_token"
	settingKeyID     = "kyrecovery_key_id"
	settingThreshold = "kyrecovery_threshold"
	settingShares    = "kyrecovery_total_shares"
	settingReceipt   = "kyrecovery_last_deposit"
)

var (
	ErrNotPaired         = errors.New("backup: pair with KyRecovery first")
	ErrKeyPinMissing     = errors.New("backup: paired recovery public key is missing")
	ErrKeyMismatch       = errors.New("backup: recovery public key does not match its pin")
	ErrRemote            = errors.New("backup: KyRecovery")
	ErrReceiptUnrecorded = errors.New("backup: deposit succeeded but receipt was not recorded")
	ErrDepositInProgress = errors.New("backup: a deposit is already in progress")
)

type Settings interface {
	GetLocalSetting(string) (string, error)
	SetLocalSetting(string, string) error
}

type Snapshotter interface{ SnapshotTo(string) error }

type RecoveryKey struct {
	Public      recoverykey.PublicKey
	Threshold   int
	TotalShares int
}

type Pairing struct {
	URL, Token string
	Key        RecoveryKey
}

type Receipt struct {
	CapsuleID   string `json:"capsule_id"`
	Digest      string `json:"digest"`
	SizeBytes   int64  `json:"size_bytes"`
	DepositedAt string `json:"deposited_at"`
}

type Status struct {
	Paired        bool     `json:"paired"`
	RecoveryURL   string   `json:"recovery_url,omitempty"`
	RecoveryKeyID string   `json:"recovery_key_id,omitempty"`
	LastDeposit   *Receipt `json:"last_deposit,omitempty"`
}

func recoveryPath(dataDir string) string { return filepath.Join(dataDir, publicKeyFile) }
func tokenKeyPath(dataDir string) string { return filepath.Join(dataDir, keyFile) }

func StoreRecoveryKey(settings Settings, dataDir string, k RecoveryKey) error {
	if k.Public.IsZero() || k.Threshold < 2 || k.TotalShares < k.Threshold || k.TotalShares > 255 {
		return errors.New("backup: invalid recovery key or custodian topology")
	}
	pinned, err := settings.GetLocalSetting(settingKeyID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	if err == nil && pinned != k.Public.ID() {
		return fmt.Errorf("%w: already pinned to %s", fs.ErrExist, pinned)
	}
	if err := keyfile.Store(recoveryPath(dataDir), k.Public.Bytes(), keyfile.Raw); errors.Is(err, fs.ErrExist) {
		raw, loadErr := keyfile.LoadEncoded(recoveryPath(dataDir), recoverykey.PublicKeyBytes, keyfile.Raw)
		if loadErr != nil {
			return loadErr
		}
		existing, parseErr := recoverykey.ParsePublicKey(raw)
		if parseErr != nil || existing.ID() != k.Public.ID() {
			return ErrKeyMismatch
		}
	} else if err != nil {
		return err
	}
	if err := settings.SetLocalSetting(settingKeyID, k.Public.ID()); err != nil {
		return err
	}
	if err := settings.SetLocalSetting(settingThreshold, strconv.Itoa(k.Threshold)); err != nil {
		return err
	}
	return settings.SetLocalSetting(settingShares, strconv.Itoa(k.TotalShares))
}

func LoadRecoveryKey(settings Settings, dataDir string) (RecoveryKey, error) {
	id, err := settings.GetLocalSetting(settingKeyID)
	if errors.Is(err, store.ErrNotFound) {
		return RecoveryKey{}, ErrNotPaired
	}
	if err != nil {
		return RecoveryKey{}, err
	}
	raw, err := keyfile.LoadEncoded(recoveryPath(dataDir), recoverykey.PublicKeyBytes, keyfile.Raw)
	if errors.Is(err, fs.ErrNotExist) {
		return RecoveryKey{}, ErrKeyPinMissing
	}
	if err != nil {
		return RecoveryKey{}, err
	}
	pub, err := recoverykey.ParsePublicKey(raw)
	if err != nil {
		return RecoveryKey{}, err
	}
	if pub.ID() != id {
		return RecoveryKey{}, ErrKeyMismatch
	}
	threshold, err := intSetting(settings, settingThreshold)
	if err != nil {
		return RecoveryKey{}, err
	}
	shares, err := intSetting(settings, settingShares)
	if err != nil {
		return RecoveryKey{}, err
	}
	return RecoveryKey{Public: pub, Threshold: threshold, TotalShares: shares}, nil
}

func intSetting(settings Settings, key string) (int, error) {
	v, err := settings.GetLocalSetting(key)
	if errors.Is(err, store.ErrNotFound) {
		return 0, ErrNotPaired
	}
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(v)
}

func sealToken(dataDir, token string) (string, error) {
	key, err := keyfile.LoadOrCreate(tokenKeyPath(dataDir), 32)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := aead.Seal(nonce, nonce, []byte(token), []byte(serviceName+":kyrecovery_token"))
	return base64.RawStdEncoding.EncodeToString(sealed), nil
}

func openToken(dataDir, encoded string) (string, error) {
	key, err := keyfile.Load(tokenKeyPath(dataDir), 32)
	if err != nil {
		return "", err
	}
	raw, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	if len(raw) < aead.NonceSize() {
		return "", errors.New("backup: invalid sealed token")
	}
	plain, err := aead.Open(nil, raw[:aead.NonceSize()], raw[aead.NonceSize():], []byte(serviceName+":kyrecovery_token"))
	return string(plain), err
}

func StorePairing(settings Settings, dataDir, serverURL, token string, key RecoveryKey) error {
	if err := StoreRecoveryKey(settings, dataDir, key); err != nil {
		return err
	}
	sealed, err := sealToken(dataDir, token)
	if err != nil {
		return err
	}
	if err := settings.SetLocalSetting(settingURL, serverURL); err != nil {
		return err
	}
	return settings.SetLocalSetting(settingToken, sealed)
}

func LoadPairing(settings Settings, dataDir string) (Pairing, error) {
	key, err := LoadRecoveryKey(settings, dataDir)
	if err != nil {
		return Pairing{}, err
	}
	u, err := settings.GetLocalSetting(settingURL)
	if errors.Is(err, store.ErrNotFound) {
		return Pairing{}, ErrNotPaired
	}
	if err != nil {
		return Pairing{}, err
	}
	sealed, err := settings.GetLocalSetting(settingToken)
	if errors.Is(err, store.ErrNotFound) {
		return Pairing{}, ErrNotPaired
	}
	if err != nil {
		return Pairing{}, err
	}
	token, err := openToken(dataDir, sealed)
	if err != nil {
		return Pairing{}, err
	}
	return Pairing{URL: u, Token: token, Key: key}, nil
}

func Collect(cfg *config.Config, snapshots Snapshotter, version string) ([]capsule.File, map[string]any, map[string]any, error) {
	if _, err := keyfile.LoadOrCreate(tokenKeyPath(cfg.DataDir), 32); err != nil {
		return nil, nil, nil, err
	}
	tmp, err := os.MkdirTemp(cfg.DataDir, ".backup-*")
	if err != nil {
		return nil, nil, nil, err
	}
	defer os.RemoveAll(tmp)
	dbPath := filepath.Join(tmp, "kydns.db")
	if err := snapshots.SnapshotTo(dbPath); err != nil {
		return nil, nil, nil, err
	}
	db, err := os.ReadFile(dbPath)
	if err != nil {
		return nil, nil, nil, err
	}
	manifest, err := yaml.Marshal(map[string]any{"data_dir": cfg.DataDir, "dns": map[string]string{"listen": cfg.DNS.Listen}, "admin": map[string]string{"listen": cfg.Admin.Listen}})
	if err != nil {
		return nil, nil, nil, err
	}
	files := []capsule.File{{Path: "data/kydns.db", Content: db, Mode: 0600}, {Path: "config/kydns.yaml", Content: manifest, Mode: 0600}}
	for _, name := range []string{keyFile} {
		b, err := os.ReadFile(filepath.Join(cfg.DataDir, name))
		if err != nil {
			return nil, nil, nil, fmt.Errorf("required backup member %s: %w", name, err)
		}
		files = append(files, capsule.File{Path: "data/" + name, Content: b, Mode: 0600})
	}
	if b, err := os.ReadFile(filepath.Join(cfg.DataDir, "node_key")); err == nil {
		files = append(files, capsule.File{Path: "data/node_key", Content: b, Mode: 0600})
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, nil, nil, err
	}
	deps := map[string]any{"ports": []string{cfg.DNS.Listen, cfg.Admin.Listen}}
	required := []string{"data/kydns.db", "data/backup_key", "config/kydns.yaml"}
	for _, f := range files {
		if f.Path == "data/node_key" {
			required = append(required, f.Path)
		}
	}
	recipe := map[string]any{"check_sqlite_integrity": true, "sqlite_paths": []string{"data/kydns.db"}, "required_files": required}
	_ = version
	return files, deps, recipe, nil
}

type DrillResult struct {
	Passed bool     `json:"passed"`
	Checks []string `json:"checks"`
}

// Drill proves collection, authenticated opening, extraction, and SQLite integrity with
// an ephemeral key. It never needs or reconstructs the suite recovery private key.
func Drill(cfg *config.Config, snapshots Snapshotter, version string) (DrillResult, error) {
	files, deps, recipe, err := Collect(cfg, snapshots, version)
	if err != nil {
		return DrillResult{}, err
	}
	private, err := recoverykey.Generate()
	if err != nil {
		return DrillResult{}, err
	}
	raw, manifest, err := capsule.Seal(serviceName, version, files, deps, recipe, 2, 3, private.Public())
	if err != nil {
		return DrillResult{}, err
	}
	target, err := os.MkdirTemp(cfg.DataDir, ".drill-*")
	if err != nil {
		return DrillResult{}, err
	}
	if err := os.Remove(target); err != nil {
		return DrillResult{}, err
	}
	defer os.RemoveAll(target)
	opened, _, err := capsule.Open(raw, private, target)
	if err != nil {
		return DrillResult{}, err
	}
	if opened.CapsuleID != manifest.CapsuleID || opened.ServiceName != serviceName {
		return DrillResult{}, errors.New("backup: drill manifest mismatch")
	}
	db, err := store.Open(filepath.Join(target, "data", "kydns.db"))
	if err != nil {
		return DrillResult{}, err
	}
	defer db.Close()
	if err := db.IntegrityCheck(); err != nil {
		return DrillResult{}, err
	}
	return DrillResult{Passed: true, Checks: []string{"snapshot", "authenticated capsule", "safe extraction", "sqlite integrity"}}, nil
}

func Seal(cfg *config.Config, snapshots Snapshotter, version string, key RecoveryKey) ([]byte, capsule.Manifest, error) {
	files, deps, recipe, err := Collect(cfg, snapshots, version)
	if err != nil {
		return nil, capsule.Manifest{}, err
	}
	return capsule.Seal(serviceName, version, files, deps, recipe, key.Threshold, key.TotalShares, key.Public)
}

type Depositor interface {
	Deposit(context.Context, string, string, []byte) (Receipt, error)
}

var depositMu sync.Mutex

func Deposit(ctx context.Context, cfg *config.Config, settings Settings, snapshots Snapshotter, client Depositor, version string) (Receipt, capsule.Manifest, error) {
	if !depositMu.TryLock() {
		return Receipt{}, capsule.Manifest{}, ErrDepositInProgress
	}
	defer depositMu.Unlock()
	p, err := LoadPairing(settings, cfg.DataDir)
	if err != nil {
		return Receipt{}, capsule.Manifest{}, err
	}
	raw, manifest, err := Seal(cfg, snapshots, version, p.Key)
	if err != nil {
		return Receipt{}, capsule.Manifest{}, err
	}
	receipt, err := client.Deposit(ctx, p.URL, p.Token, raw)
	if err != nil {
		return Receipt{}, manifest, err
	}
	if receipt.CapsuleID != manifest.CapsuleID {
		return Receipt{}, manifest, fmt.Errorf("%w: receipt names the wrong capsule", ErrRemote)
	}
	b, _ := json.Marshal(receipt)
	if err := settings.SetLocalSetting(settingReceipt, string(b)); err != nil {
		return receipt, manifest, fmt.Errorf("%w: %v", ErrReceiptUnrecorded, err)
	}
	return receipt, manifest, nil
}

func ReadStatus(settings Settings) (Status, error) {
	s := Status{}
	if id, err := settings.GetLocalSetting(settingKeyID); err == nil {
		s.Paired, s.RecoveryKeyID = true, id
	} else if !errors.Is(err, store.ErrNotFound) {
		return s, err
	}
	if u, err := settings.GetLocalSetting(settingURL); err == nil {
		s.RecoveryURL = u
	} else if !errors.Is(err, store.ErrNotFound) {
		return s, err
	}
	if raw, err := settings.GetLocalSetting(settingReceipt); err == nil {
		var r Receipt
		if err := json.Unmarshal([]byte(raw), &r); err != nil {
			return s, err
		}
		s.LastDeposit = &r
	} else if !errors.Is(err, store.ErrNotFound) {
		return s, err
	}
	return s, nil
}
