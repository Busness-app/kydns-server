package web

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/Busness-app/ky-primitives/recoveryclient"
	"github.com/Busness-app/ky-primitives/recoverykey"
	"github.com/Busness-app/kydns-server/internal/backup"
	"github.com/Busness-app/kydns-server/internal/config"
)

// loggedInWithBackup is loggedIn with a real backup.Service over the test store. dir is
// KYDNS_BACKUP_DIR: empty means this node has nowhere to put a capsule.
func loggedInWithBackup(t *testing.T, dir string) (http.Handler, *Server, *http.Cookie, string) {
	t.Helper()
	data := t.TempDir()
	return loggedIn(t, func(o *Options) {
		cfg := &config.Config{DataDir: data, BackupDir: dir, BackupKeep: 7}
		b, err := backup.New(cfg, o.Store, "test")
		if err != nil {
			t.Fatal(err)
		}
		o.Backup = b
	})
}

// freshPublicKeyB64 is a throwaway suite recovery public key in the ceremony page's encoding.
func freshPublicKeyB64(t *testing.T) string {
	t.Helper()
	priv, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(priv.Public().Bytes())
}

func pinViaService(t *testing.T, srv *Server) {
	t.Helper()
	if _, err := srv.o.Backup.PinKey(freshPublicKeyB64(t), 2, 3); err != nil {
		t.Fatal(err)
	}
}

func TestBackupSectionWarnsWithoutKeyAndDestination(t *testing.T) {
	h, _, c, _ := loggedInWithBackup(t, "")
	body := get(t, h, "/settings", c).Body.String()
	for _, want := range []string{"No recovery key", "Nowhere to put a capsule", "Pin the suite key by hand"} {
		if !strings.Contains(body, want) {
			t.Errorf("settings page lacks %q", want)
		}
	}
}

func TestBackupPinKeyThenRunWritesLocalCopy(t *testing.T) {
	dir := t.TempDir()
	h, srv, c, csrf := loggedInWithBackup(t, dir)
	rr := postForm(t, h, "/settings/backup/pin-key", url.Values{"public_key": {freshPublicKeyB64(t)}, "threshold": {"2"}, "total_shares": {"3"}, "csrf_token": {csrf}}, c)
	if rr.Code != 303 {
		t.Fatalf("pin-key = %d %s", rr.Code, rr.Body)
	}
	rr = postForm(t, h, "/settings/backup/deposit", url.Values{"csrf_token": {csrf}}, c)
	if rr.Code != 303 {
		t.Fatalf("run = %d %s", rr.Code, rr.Body)
	}
	copies, _ := recoveryclient.ListLocalCopies(dir, backup.ServiceName)
	if len(copies) != 1 {
		t.Fatalf("copies = %d", len(copies))
	}
	body := get(t, h, "/settings", c).Body.String()
	if !strings.Contains(body, copies[0].Name) || !strings.Contains(body, "Schedule") {
		t.Fatal("settings page does not show the local copy and schedule card")
	}
	_ = srv
}

func TestBackupPostsNeedCSRF(t *testing.T) {
	h, _, c, _ := loggedInWithBackup(t, "")
	for _, p := range []string{"/settings/backup/pin-key", "/settings/backup/unpair", "/settings/backup/schedule", "/settings/backup/deposit", "/settings/backup/drill", "/settings/backup/pair"} {
		if rr := postForm(t, h, p, url.Values{}, c); rr.Code != 403 {
			t.Errorf("%s without csrf = %d", p, rr.Code)
		}
	}
}

func TestBackupPageNeverShowsTheToken(t *testing.T) {
	h, srv, c, _ := loggedInWithBackup(t, "")
	pinViaService(t, srv)
	if err := recoveryclient.StorePairing(srv.o.Backup.Settings(), srv.o.Backup.Sealer(), "https://recovery.example", "plain-secret-token"); err != nil {
		t.Fatal(err)
	}
	body := get(t, h, "/settings", c).Body.String()
	if strings.Contains(body, "plain-secret-token") {
		t.Fatal("token rendered")
	}
	if !strings.Contains(body, "recovery.example") || !strings.Contains(body, "Unpair") {
		t.Fatal("pairing panel missing")
	}
}

func TestBackupScheduleFormRejectsBelowFloor(t *testing.T) {
	h, _, c, csrf := loggedInWithBackup(t, "")
	rr := postForm(t, h, "/settings/backup/schedule", url.Values{"interval_minutes": {"5"}, "csrf_token": {csrf}}, c)
	if rr.Code != 400 || !strings.Contains(rr.Body.String(), "15") {
		t.Fatalf("schedule 5m = %d %s", rr.Code, rr.Body)
	}
}

// A private KyRecovery URL is refused before the pairing code is presented to it, and the
// switch that would admit it is named.
func TestBackupPairRefusesAPrivateURLAndNamesTheSwitch(t *testing.T) {
	h, _, c, csrf := loggedInWithBackup(t, "")
	rr := postForm(t, h, "/settings/backup/pair", url.Values{
		"recovery_url": {"https://192.168.1.9"}, "pairing_code": {"123456"}, "csrf_token": {csrf}}, c)
	if rr.Code != 400 || !strings.Contains(rr.Body.String(), "KYDNS_BACKUP_ALLOW_PRIVATE_RECOVERY") {
		t.Fatalf("pair private = %d %s", rr.Code, rr.Body)
	}
}

func TestBackupTemplateHasNoInlineHandlers(t *testing.T) {
	b, _ := os.ReadFile("templates/settings.html")
	if regexp.MustCompile(`\son[a-z]+=`).Match(b) {
		t.Fatal("inline event handler in settings.html")
	}
}
