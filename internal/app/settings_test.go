package app

import (
	"bytes"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/miekg/dns"

	"github.com/yoshiofthewire/kydns-server/internal/config"
	"github.com/yoshiofthewire/kydns-server/internal/dnsserver"
	"github.com/yoshiofthewire/kydns-server/internal/store"
)

func testStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "kydns.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func testConfig(t *testing.T, body string) *config.Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "kydns.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestEnsureSettingsSeedsOnce(t *testing.T) {
	st := testStore(t)
	cfg := testConfig(t, "data_dir: "+t.TempDir()+"\ndns:\n  private_domain: first.example\n")

	boot, err := ensureSettings(st, cfg, slog.Default())
	if err != nil {
		t.Fatalf("first run: %v", err)
	}
	if boot.PrivateDomain != "first.example" {
		t.Fatalf("the file did not seed the database: %+v", boot)
	}

	// An operator edits the value in the UI.
	stored, _, err := st.Settings()
	if err != nil {
		t.Fatal(err)
	}
	stored.PrivateDomain = "edited.example"
	if err := st.PutSettings(stored); err != nil {
		t.Fatal(err)
	}

	// A second start with a different file must not overwrite it. This is the
	// whole precedence rule: the database wins, the file seeds once.
	cfg2 := testConfig(t, "data_dir: "+t.TempDir()+"\ndns:\n  private_domain: second.example\n")
	boot, err = ensureSettings(st, cfg2, slog.Default())
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if boot.PrivateDomain != "edited.example" {
		t.Errorf("the config file overwrote a stored setting: %q", boot.PrivateDomain)
	}
}

// logCapture collects what startup told the operator, so the tests can assert
// on the warning that is now the only signal a public ACL is in force.
func logCapture(t *testing.T) (*slog.Logger, func() string) {
	t.Helper()
	var mu sync.Mutex
	var buf bytes.Buffer
	h := slog.NewTextHandler(&syncWriter{mu: &mu, w: &buf}, nil)
	return slog.New(h), func() string {
		mu.Lock()
		defer mu.Unlock()
		return buf.String()
	}
}

type syncWriter struct {
	mu *sync.Mutex
	w  *bytes.Buffer
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

// An ACL that was legal when the operator wrote it keeps working on upgrade:
// taking a running resolver offline is itself destructive. The warning is what
// keeps the exposure visible.
func TestEnsureSettingsGrandfathersAPublicSeed(t *testing.T) {
	st := testStore(t)
	cfg := testConfig(t, "data_dir: "+t.TempDir()+"\ndns:\n  allow_query: [\"0.0.0.0/0\"]\n")

	logger, logged := logCapture(t)
	boot, err := ensureSettings(st, cfg, logger)
	if err != nil {
		t.Fatalf("a public ACL already in the config file must still start: %v", err)
	}
	if len(boot.AllowQuery) != 1 || boot.AllowQuery[0] != "0.0.0.0/0" {
		t.Fatalf("the seed did not keep the configured ACL: %+v", boot.AllowQuery)
	}
	out := logged()
	if !strings.Contains(out, "open resolver") || !strings.Contains(out, "0.0.0.0/0") {
		t.Errorf("startup did not warn about the public range: %s", out)
	}
}

// A prefix is stored the way the ACL reads it. The seed is the upgrade path,
// so an entry like 192.168.1.99/0 must not sit in the database reading as a
// single LAN host while enforcing 0.0.0.0/0.
func TestEnsureSettingsCanonicalizesTheSeed(t *testing.T) {
	st := testStore(t)
	cfg := testConfig(t, "data_dir: "+t.TempDir()+
		"\ndns:\n  allow_query: [\"192.168.1.99/0\"]\n  reverse_zones: [\"192.168.1.5/24\"]\n")

	boot, err := ensureSettings(st, cfg, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	stored, ok, err := st.Settings()
	if err != nil || !ok {
		t.Fatalf("settings not stored: %v", err)
	}
	for _, got := range []store.Settings{boot, stored} {
		if got.AllowQuery[0] != "0.0.0.0/0" {
			t.Errorf("allow_query stored as %q, want the masked form", got.AllowQuery[0])
		}
		if got.ReverseZones[0] != "192.168.1.0/24" {
			t.Errorf("reverse_zones stored as %q, want the masked form", got.ReverseZones[0])
		}
	}
}

// The file's moved keys are ignored once the database holds settings, so a
// bogus one in a tidied YAML must not keep a working server from starting.
func TestBogusMovedKeyDoesNotBlockASeededStart(t *testing.T) {
	st := testStore(t)
	dir := t.TempDir()
	if _, err := ensureSettings(st, testConfig(t, "data_dir: "+dir+"\n"), slog.Default()); err != nil {
		t.Fatal(err)
	}
	cfg := testConfig(t, "data_dir: "+dir+"\ndns:\n  allow_query: [\"totally bogus\"]\n"+
		"  upstreams: [\"1.1.1.1:no\"]\n")
	if _, err := ensureSettings(st, cfg, slog.Default()); err != nil {
		t.Fatalf("a seeded database refused to start over an ignored file key: %v", err)
	}
}

// Grandfathering waives the confirmation and nothing else. Every arm here is a
// value config.Load now accepts, because the file no longer owns these keys:
// the seed validator is the only thing standing between them and a
// half-configured server on a fresh database.
func TestEnsureSettingsRejectsAnInvalidSeed(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"malformed cidr", "dns:\n  allow_query: [\"192.168.0.0\"]\n"},
		{"bad upstream", "dns:\n  upstreams: [\"tls://example.com\"]\n"},
		{"negative ttl", "dns:\n  ttl: -1\n"},
		{"relative lease path", "discovery:\n  dhcp_lease_file: leases\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := testStore(t)
			path := filepath.Join(t.TempDir(), "kydns.yaml")
			body := "data_dir: " + t.TempDir() + "\n" + tc.body
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := config.Load(path)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if _, err := ensureSettings(st, cfg, slog.Default()); err == nil {
				t.Fatal("an invalid value was seeded from the file with no complaint")
			}
		})
	}
}

// A stored public prefix arrived through a confirmed save or a seed, so it is
// honoured and warned about, not refused.
func TestEnsureSettingsGrandfathersAPublicStoredACL(t *testing.T) {
	st := testStore(t)
	cfg := testConfig(t, "data_dir: "+t.TempDir()+"\n")
	boot, err := ensureSettings(st, cfg, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	boot.AllowQuery = []string{"192.168.0.0/16", "8.8.8.0/24"}
	if err := st.PutSettings(boot); err != nil {
		t.Fatal(err)
	}

	logger, logged := logCapture(t)
	got, err := ensureSettings(st, cfg, logger)
	if err != nil {
		t.Fatalf("a stored public ACL must still start: %v", err)
	}
	if len(got.AllowQuery) != 2 {
		t.Fatalf("the stored ACL was not honoured: %+v", got.AllowQuery)
	}
	if out := logged(); !strings.Contains(out, "8.8.8.0/24") {
		t.Errorf("startup did not warn about the public range: %s", out)
	}
}

// A database edited by hand, or written by an older version, must not start a
// half-configured server.
func TestEnsureSettingsRejectsInvalidStoredSettings(t *testing.T) {
	for _, mut := range []struct {
		name string
		fn   func(*store.Settings)
	}{
		// Default-closed: an empty allow list refuses every query.
		{"empty allow_query", func(s *store.Settings) { s.AllowQuery = nil }},
		{"malformed cidr", func(s *store.Settings) { s.AllowQuery = []string{"192.168.0.0"} }},
		{"no upstreams", func(s *store.Settings) { s.Upstreams = nil }},
		{"zero ttl", func(s *store.Settings) { s.TTL = 0 }},
	} {
		t.Run(mut.name, func(t *testing.T) {
			st := testStore(t)
			cfg := testConfig(t, "data_dir: "+t.TempDir()+"\n")
			boot, err := ensureSettings(st, cfg, slog.Default())
			if err != nil {
				t.Fatal(err)
			}
			mut.fn(&boot)
			if err := st.PutSettings(boot); err != nil {
				t.Fatal(err)
			}
			if _, err := ensureSettings(st, cfg, slog.Default()); err == nil {
				t.Fatal("an invalid stored settings row started the server")
			}
		})
	}
}

// An operator who walks away from an upstream they no longer trust must not
// keep being served that resolver's answers for up to cache_max_ttl.
func TestFlushOnUpstreamChange(t *testing.T) {
	q := dns.Question{Name: "kypost.home.arpa.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	answer := func() *dns.Msg {
		m := new(dns.Msg)
		m.SetQuestion(q.Name, dns.TypeA)
		m.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP("192.168.1.20"),
		}}
		return m
	}

	prev := []string{"tls://1.1.1.1:853"}
	for _, tc := range []struct {
		name      string
		next      []string
		wantFlush bool
	}{
		{"a changed upstream flushes", []string{"tls://9.9.9.9:853"}, true},
		{"an added upstream flushes", []string{"tls://1.1.1.1:853", "tls://9.9.9.9:853"}, true},
		{"an unrelated save keeps the cache", []string{"tls://1.1.1.1:853"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := dnsserver.NewCache(10, 5, 3600, 300)
			c.Put(q, false, answer())
			if c.Len() != 1 {
				t.Fatalf("the fixture did not cache: %d entries", c.Len())
			}
			if got := flushOnUpstreamChange(c, prev, tc.next, slog.Default()); got != tc.wantFlush {
				t.Errorf("flushed = %v, want %v", got, tc.wantFlush)
			}
			if want := 0; tc.wantFlush && c.Len() != want {
				t.Errorf("cache still holds %d entries after an upstream change", c.Len())
			}
			if !tc.wantFlush && c.Len() != 1 {
				t.Error("an unrelated save emptied the cache, making every client re-resolve")
			}
		})
	}
}
