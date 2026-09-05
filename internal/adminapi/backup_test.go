package adminapi

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Busness-app/ky-primitives/recoveryclient"
	"github.com/Busness-app/ky-primitives/recoverykey"
	"github.com/Busness-app/kydns-server/internal/backup"
	"github.com/Busness-app/kydns-server/internal/config"
	"github.com/Busness-app/kydns-server/internal/registry"
	"github.com/Busness-app/kydns-server/internal/store"
)

// backupEnv is one API with a real store and a real backup.Service behind it.
// dbPath is kept so a test can read the audit table, and break it, through a
// second connection: the store's handle is unexported and this package is not
// store's.
type backupEnv struct {
	h      http.Handler
	tok    string
	dbPath string
}

// backupAPI builds an authed API whose backup service writes into t.TempDir().
// tweak may be nil; it is where a test sets BackupDir or the private opt-in.
func backupAPI(t *testing.T, tweak func(*config.Config)) (backupEnv, string) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "kydns.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	cfg := &config.Config{DataDir: dir, BackupKeep: 7}
	cfg.DNS.Listen, cfg.Admin.Listen = "127.0.0.1:5353", "127.0.0.1:8443"
	if tweak != nil {
		tweak(cfg)
	}
	svc, err := backup.New(cfg, st, "test")
	if err != nil {
		t.Fatal(err)
	}
	reg := registry.New(st, "home.arpa.", func() error { return nil })
	tok, err := reg.CreateToken("test")
	if err != nil {
		t.Fatal(err)
	}
	api := NewAPI(reg, nil, nil).WithBackupService(svc)
	return backupEnv{h: api.Handler(), tok: tok, dbPath: dbPath}, tok
}

// pinKeyReq is a pin request for a freshly generated recovery key, so two
// calls name two different keys.
func pinKeyReq(t *testing.T) string {
	t.Helper()
	k, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(map[string]any{
		"public_key":   base64.StdEncoding.EncodeToString(k.Public().Bytes()),
		"threshold":    2,
		"total_shares": 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// backupDB opens a second connection to the same file. The store runs in WAL,
// so a reader alongside the live handle is safe.
func backupDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// auditRows is every audit event as "action details", newline separated.
func auditRows(t *testing.T, e backupEnv) string {
	t.Helper()
	return auditQuery(t, e, `SELECT action || ' ' || details FROM audit_events ORDER BY id`)
}

func auditQuery(t *testing.T, e backupEnv, q string) string {
	t.Helper()
	rows, err := backupDB(t, e.dbPath).Query(q)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return strings.Join(out, "\n")
}

// auditOutcomes is every audit event as "action outcome", newline separated.
func auditOutcomes(t *testing.T, e backupEnv) string {
	t.Helper()
	return auditQuery(t, e, `SELECT action || ' ' || outcome FROM audit_events ORDER BY id`)
}

// breakAudit makes every audit write fail, which is the only way to test that
// a capsule is not streamed to a caller whose download went unrecorded.
func breakAudit(t *testing.T, e backupEnv) {
	t.Helper()
	if _, err := backupDB(t, e.dbPath).Exec(`DROP TABLE audit_events`); err != nil {
		t.Fatal(err)
	}
}

func TestBackupStatusRedactsAndReportsNoDestination(t *testing.T) {
	e, tok := backupAPI(t, nil)
	if rr := do(t, e.h, "POST", "/api/v1/backup/pin-key", tok, pinKeyReq(t)); rr.Code != 200 {
		t.Fatalf("pin-key = %d %s", rr.Code, rr.Body)
	}
	rr := do(t, e.h, "GET", "/api/v1/backup/status", tok, "")
	var st backup.Status
	if err := json.Unmarshal(rr.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if !st.KeyPinned || st.HasDestination {
		t.Fatalf("status = %+v", st)
	}
	if strings.Contains(rr.Body.String(), "token") {
		t.Fatal("status body mentions a token")
	}
	rr = do(t, e.h, "POST", "/api/v1/backup/deposit", tok, "")
	if rr.Code != 412 || !strings.Contains(rr.Body.String(), "KYDNS_BACKUP_DIR") {
		t.Fatalf("deposit with no destination = %d %s", rr.Code, rr.Body)
	}
}

func TestBackupPinKeyIsWriteOnce(t *testing.T) {
	e, tok := backupAPI(t, nil)
	do(t, e.h, "POST", "/api/v1/backup/pin-key", tok, pinKeyReq(t))
	if rr := do(t, e.h, "POST", "/api/v1/backup/pin-key", tok, pinKeyReq(t)); rr.Code != 409 {
		t.Fatalf("second pin = %d %s", rr.Code, rr.Body)
	}
}

func TestBackupScheduleReadsBack(t *testing.T) {
	e, tok := backupAPI(t, nil)
	for _, body := range []string{`{"interval_sec": 60}`, `{"interval_sec": -5}`, `{"interval_sec": 36028797018963968}`} {
		if rr := do(t, e.h, "PUT", "/api/v1/backup/schedule", tok, body); rr.Code != 400 {
			t.Errorf("%s = %d", body, rr.Code)
		}
	}
	rr := do(t, e.h, "PUT", "/api/v1/backup/schedule", tok, `{"interval_sec": 3600}`)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"interval_sec":3600`) {
		t.Fatalf("schedule = %d %s", rr.Code, rr.Body)
	}
	events := auditRows(t, e)
	if !strings.Contains(events, "backup.schedule") || !strings.Contains(events, "3600") {
		t.Fatalf("audit rows = %s", events)
	}
}

func TestBackupUnpairWhenNeverPairedIs412(t *testing.T) {
	e, tok := backupAPI(t, nil)
	if rr := do(t, e.h, "DELETE", "/api/v1/backup/pairing", tok, ""); rr.Code != 412 {
		t.Fatalf("unpair = %d %s", rr.Code, rr.Body)
	}
}

func TestBackupRunWithLocalDirWritesAndAudits(t *testing.T) {
	dir := t.TempDir()
	e, tok := backupAPI(t, func(c *config.Config) { c.BackupDir = dir })
	do(t, e.h, "POST", "/api/v1/backup/pin-key", tok, pinKeyReq(t))
	rr := do(t, e.h, "POST", "/api/v1/backup/deposit", tok, "")
	if rr.Code != 200 {
		t.Fatalf("run = %d %s", rr.Code, rr.Body)
	}
	copies, err := recoveryclient.ListLocalCopies(dir, backup.ServiceName)
	if err != nil {
		t.Fatal(err)
	}
	if len(copies) != 1 {
		t.Fatalf("copies = %d", len(copies))
	}
	if !strings.Contains(auditRows(t, e), "admin.backup_run") {
		t.Fatalf("run not audited: %s", auditRows(t, e))
	}
}

func TestBackupExportRefusedWhenAuditFails(t *testing.T) {
	e, tok := backupAPI(t, nil)
	do(t, e.h, "POST", "/api/v1/backup/pin-key", tok, pinKeyReq(t))
	breakAudit(t, e)
	rr := do(t, e.h, "GET", "/api/v1/backup/export-capsule", tok, "")
	if rr.Code != 503 || rr.Body.Len() > 512 {
		t.Fatalf("export with broken audit = %d, %d bytes", rr.Code, rr.Body.Len())
	}
}

// A recovery URL this node must not send a capsule to is refused before any
// network call, leaves no pin behind, and is still audited: probing pair-remote
// for which destinations this node accepts must leave the same trail as pairing
// with one. The switch is named only for an address it would actually admit.
func TestBackupPairRefusesUnusableRecoveryURLs(t *testing.T) {
	for _, tc := range []struct {
		url         string
		namesSwitch bool
	}{
		{"http://example.com", false},
		{"https://example.com/?x=1", false},
		// Loopback is refused with or without the opt-in, so naming it would send
		// the operator to set a variable that changes nothing.
		{"https://127.0.0.1", false},
		{"https://192.168.1.10", true},
	} {
		e, tok := backupAPI(t, nil)
		body, err := json.Marshal(map[string]string{"recovery_url": tc.url, "pairing_code": "123456"})
		if err != nil {
			t.Fatal(err)
		}
		rr := do(t, e.h, "POST", "/api/v1/backup/pair-remote", tok, string(body))
		if rr.Code != http.StatusBadRequest && rr.Code != http.StatusBadGateway {
			t.Errorf("pair %s = %d, want 400 or 502: %s", tc.url, rr.Code, rr.Body)
		}
		if named := strings.Contains(rr.Body.String(), "KYDNS_BACKUP_ALLOW_PRIVATE_RECOVERY"); named != tc.namesSwitch {
			t.Errorf("pair %s names the switch = %v, want %v: %s", tc.url, named, tc.namesSwitch, rr.Body)
		}
		rows := auditRows(t, e)
		if !strings.Contains(rows, "backup.paired") || !strings.Contains(rows, "allow_private=false") {
			t.Errorf("pair %s left no audit row: %q", tc.url, rows)
		}
		if n := strings.Count(rows, "backup.paired"); n != 1 {
			t.Errorf("pair %s wrote %d backup.paired rows, want 1: %q", tc.url, n, rows)
		}
		if !strings.Contains(auditOutcomes(t, e), "backup.paired failure") {
			t.Errorf("pair %s was not audited as a failure: %s", tc.url, auditOutcomes(t, e))
		}
		var st backup.Status
		sr := do(t, e.h, "GET", "/api/v1/backup/status", tok, "")
		if err := json.Unmarshal(sr.Body.Bytes(), &st); err != nil {
			t.Fatal(err)
		}
		if st.KeyPinned || st.Paired {
			t.Errorf("pair %s left state behind: %+v", tc.url, st)
		}
	}
}
