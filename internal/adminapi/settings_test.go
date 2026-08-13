package adminapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yoshiofthewire/kydns-server/internal/dnsserver"
	"github.com/yoshiofthewire/kydns-server/internal/registry"
	"github.com/yoshiofthewire/kydns-server/internal/settings"
	"github.com/yoshiofthewire/kydns-server/internal/store"
)

// testSrv is a small authenticated-request helper, matching how newAPI/do work
// in api_test.go but bundling the handler and token together so settings
// tests read as srv.do(t, method, path, body).
type testSrv struct {
	h   http.Handler
	tok string
}

func (s *testSrv) do(t *testing.T, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	return do(t, s.h, method, path, s.tok, body)
}

func validStoredSettings() store.Settings {
	return store.Settings{
		PrivateDomain:     "home.arpa",
		ReverseZones:      []string{"192.168.1.0/24"},
		Upstreams:         []string{"udp://1.1.1.1:53"},
		AllowQuery:        []string{"192.168.0.0/16"},
		TTL:               300,
		CacheMinTTL:       1,
		CacheMaxTTL:       3600,
		NegativeMaxTTL:    60,
		CacheEntries:      1000,
		DiscoveryInterval: 60,
		HealthInterval:    30,
		HealthTimeout:     5,
		HealthWorkers:     4,
	}
}

// testAPIWithSettings builds an API with a real store, a settings.Service over
// it, and a bearer token, matching the shape of newAPI in api_test.go.
func testAPIWithSettings(t *testing.T) (*testSrv, *settings.Service) {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "kydns.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err := s.PutSettings(validStoredSettings()); err != nil {
		t.Fatal(err)
	}
	reg := registry.New(s, "home.arpa.", func() error { return nil })
	tok, err := reg.CreateToken("test")
	if err != nil {
		t.Fatal(err)
	}

	h := settings.NewHolder(func() (store.Settings, error) {
		v, _, err := s.Settings()
		return v, err
	})
	if err := h.Rebuild(); err != nil {
		t.Fatal(err)
	}
	svc := settings.NewService(s, h, nil)

	api := NewAPI(reg, nil, nil).WithSettings(svc)
	return &testSrv{h: api.Handler(), tok: tok}, svc
}

func TestGetSettings(t *testing.T) {
	srv, _ := testAPIWithSettings(t)

	rec := srv.do(t, "GET", "/api/v1/settings", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["private_domain"] != "home.arpa" {
		t.Errorf("private_domain: %v", got["private_domain"])
	}
	if _, ok := got["upstreams"].([]any); !ok {
		t.Errorf("upstreams is not a list: %T", got["upstreams"])
	}
}

// PATCH merges: an absent key keeps its value, matching the blacklist settings
// endpoint and PATCH /services/{id}.
func TestPatchSettingsIsPartial(t *testing.T) {
	srv, svc := testAPIWithSettings(t)

	rec := srv.do(t, "PATCH", "/api/v1/settings", `{"ttl":120}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	cur, err := svc.Get()
	if err != nil {
		t.Fatal(err)
	}
	if cur.TTL != 120 {
		t.Errorf("ttl not applied: %d", cur.TTL)
	}
	if cur.PrivateDomain != "home.arpa" {
		t.Errorf("an absent key was clobbered: %q", cur.PrivateDomain)
	}
	if len(cur.Upstreams) == 0 {
		t.Error("an absent list was emptied")
	}
}

// An explicit empty list is a real instruction and must clear the value.
func TestPatchSettingsExplicitEmptyList(t *testing.T) {
	srv, svc := testAPIWithSettings(t)

	rec := srv.do(t, "PATCH", "/api/v1/settings", `{"reverse_zones":[]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	cur, _ := svc.Get()
	if len(cur.ReverseZones) != 0 {
		t.Errorf("an explicit empty list did not clear: %v", cur.ReverseZones)
	}
}

func TestPatchSettingsRejectsPublicACL(t *testing.T) {
	srv, svc := testAPIWithSettings(t)
	before, _ := svc.Get()

	rec := srv.do(t, "PATCH", "/api/v1/settings", `{"allow_query":["0.0.0.0/0"]}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400: %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "allow_query") {
		t.Errorf("the error does not name the field: %s", rec.Body)
	}
	after, _ := svc.Get()
	if len(after.AllowQuery) != len(before.AllowQuery) {
		t.Error("a rejected patch still changed the stored ACL")
	}
}

func TestPatchSettingsAcceptsConfirmedPublicACL(t *testing.T) {
	srv, svc := testAPIWithSettings(t)

	rec := srv.do(t, "PATCH", "/api/v1/settings",
		`{"allow_query":["192.168.0.0/16","0.0.0.0/0"],"confirm_public":"0.0.0.0/0"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	cur, _ := svc.Get()
	if len(cur.AllowQuery) != 2 {
		t.Errorf("the confirmed ACL was not stored: %v", cur.AllowQuery)
	}
}

// The guardrail's confirmation is only informed consent if what is later
// read back is what was actually confirmed: a non-canonical entry like
// "1.2.3.4/0" behaves as 0.0.0.0/0 but reads as a single host, so it must be
// stored and returned in its masked, canonical form.
func TestPatchSettingsStoresCanonicalPrefixes(t *testing.T) {
	srv, svc := testAPIWithSettings(t)

	rec := srv.do(t, "PATCH", "/api/v1/settings",
		`{"allow_query":["192.168.0.0/16","1.2.3.4/0"],"reverse_zones":["10.0.0.99/24"],"confirm_public":"0.0.0.0/0"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}

	cur, _ := svc.Get()
	foundCanonical, foundTyped := false, false
	for _, c := range cur.AllowQuery {
		if c == "0.0.0.0/0" {
			foundCanonical = true
		}
		if c == "1.2.3.4/0" {
			foundTyped = true
		}
	}
	if !foundCanonical {
		t.Errorf("allow_query was not canonicalized: %v", cur.AllowQuery)
	}
	if foundTyped {
		t.Errorf("allow_query still stores the misleading typed form: %v", cur.AllowQuery)
	}
	if len(cur.ReverseZones) != 1 || cur.ReverseZones[0] != "10.0.0.0/24" {
		t.Errorf("reverse_zones was not canonicalized: %v", cur.ReverseZones)
	}

	// The GET response must show the same canonical form, not the typed one.
	body := srv.do(t, "GET", "/api/v1/settings", "").Body.String()
	if strings.Contains(body, "1.2.3.4/0") {
		t.Errorf("GET echoes the misleading typed form: %s", body)
	}
	if !strings.Contains(body, `"0.0.0.0/0"`) {
		t.Errorf("GET does not show the canonical confirmed prefix: %s", body)
	}
}

// confirm_public is an instruction for this request, never a stored value.
func TestConfirmPublicIsNotPersisted(t *testing.T) {
	srv, _ := testAPIWithSettings(t)
	srv.do(t, "PATCH", "/api/v1/settings",
		`{"allow_query":["192.168.0.0/16","0.0.0.0/0"],"confirm_public":"0.0.0.0/0"}`)

	rec := srv.do(t, "GET", "/api/v1/settings", "")
	if strings.Contains(rec.Body.String(), "confirm_public") {
		t.Errorf("confirm_public was echoed back as stored state: %s", rec.Body)
	}
}

// A caller must not be able to defeat the guardrail by feeding back its own
// allow_query as the confirmation: the handler must pass exactly what the
// client sent in confirm_public, never anything derived from the request.
func TestConfirmPublicCannotBeSelfSupplied(t *testing.T) {
	srv, svc := testAPIWithSettings(t)
	before, _ := svc.Get()

	// No confirm_public field at all: a client cannot rely on the server
	// inferring consent from the allow_query list it just sent.
	rec := srv.do(t, "PATCH", "/api/v1/settings", `{"allow_query":["192.168.0.0/16","0.0.0.0/0"]}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400: %s", rec.Code, rec.Body)
	}
	after, _ := svc.Get()
	if len(after.AllowQuery) != len(before.AllowQuery) {
		t.Error("an unconfirmed public ACL was still stored")
	}
}

// A backup that omits settings is not a backup.
func TestExportIncludesSettings(t *testing.T) {
	srv, _ := testAPIWithSettings(t)
	rec := srv.do(t, "GET", "/api/v1/export?format=json", "")
	if !strings.Contains(rec.Body.String(), `"settings"`) {
		t.Errorf("export has no settings: %s", rec.Body)
	}
}

func TestImportRestoresSettings(t *testing.T) {
	srv, svc := testAPIWithSettings(t)
	rec := srv.do(t, "GET", "/api/v1/export?format=json", "")
	doc := rec.Body.String()

	srv.do(t, "PATCH", "/api/v1/settings", `{"ttl":999}`)
	if cur, _ := svc.Get(); cur.TTL != 999 {
		t.Fatal("setup failed")
	}

	if rec := srv.do(t, "POST", "/api/v1/import", doc); rec.Code >= 300 {
		t.Fatalf("import: %d %s", rec.Code, rec.Body)
	}
	cur, _ := svc.Get()
	if cur.TTL == 999 {
		t.Error("import did not restore the exported settings")
	}
}

// An import that carries a public allow_query prefix not already running must
// not silently install an open resolver: it needs the same confirmation a
// live edit does, so it is rejected rather than applied blind.
func TestImportRejectsUnconfirmedPublicACL(t *testing.T) {
	srv, svc := testAPIWithSettings(t)
	before, _ := svc.Get()

	doc := `{"views":[],"services":[],"records":[],"settings":{
		"private_domain":"home.arpa","reverse_zones":["192.168.1.0/24"],
		"upstreams":["udp://1.1.1.1:53"],"allow_query":["0.0.0.0/0"],
		"ttl":300,"cache_min_ttl":1,"cache_max_ttl":3600,"negative_max_ttl":60,
		"cache_entries":1000,"discovery_interval":60,"health_interval":30,
		"health_timeout":5,"health_workers":4}}`
	rec := srv.do(t, "POST", "/api/v1/import", doc)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400: %s", rec.Code, rec.Body)
	}
	after, _ := svc.Get()
	if len(after.AllowQuery) != len(before.AllowQuery) {
		t.Error("a rejected import still changed the stored ACL")
	}
}

// Merge mode writes rows one at a time, so a settings block that cannot be
// applied has to be caught before the first of them: a 400 that still leaves
// the imported service being served is worse than either outcome alone.
func TestImportMergeRejectsUnconfirmedPublicACLWithoutWritingTheRegistry(t *testing.T) {
	srv, _ := testAPIWithSettings(t)

	doc := `{"views":[],"services":[{"name":"sneaky","addresses":[{"address":"192.168.1.30"}]}],
		"records":[],"settings":{
		"private_domain":"home.arpa","reverse_zones":["192.168.1.0/24"],
		"upstreams":["udp://1.1.1.1:53"],"allow_query":["0.0.0.0/0"],
		"ttl":300,"cache_min_ttl":1,"cache_max_ttl":3600,"negative_max_ttl":60,
		"cache_entries":1000,"discovery_interval":60,"health_interval":30,
		"health_timeout":5,"health_workers":4}}`
	if rec := srv.do(t, "POST", "/api/v1/import", doc); rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400: %s", rec.Code, rec.Body)
	}
	if got := srv.do(t, "GET", "/api/v1/services", "").Body.String(); strings.Contains(got, "sneaky") {
		t.Errorf("a rejected merge import wrote the registry anyway: %s", got)
	}
}

// A replace-mode restore is the bare-metal-restore path: it must not destroy
// the registry before the guardrail has had a chance to reject the document.
// Backing this up from a moment the server was exposed is the common case,
// so this failure mode is not an edge case for that endpoint.
func TestImportReplaceRejectsUnconfirmedPublicACLWithoutWipingServices(t *testing.T) {
	srv, svc := testAPIWithSettings(t)
	before, _ := svc.Get()
	rec := srv.do(t, "POST", "/api/v1/services", `{"name":"kypost","addresses":[{"address":"192.168.1.20"}]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("setup: POST services = %d: %s", rec.Code, rec.Body)
	}

	doc := `{"views":[],"services":[{"name":"kept","addresses":[{"address":"192.168.1.30"}]}],
		"records":[],"settings":{
		"private_domain":"home.arpa","reverse_zones":["192.168.1.0/24"],
		"upstreams":["udp://1.1.1.1:53"],"allow_query":["0.0.0.0/0"],
		"ttl":300,"cache_min_ttl":1,"cache_max_ttl":3600,"negative_max_ttl":60,
		"cache_entries":1000,"discovery_interval":60,"health_interval":30,
		"health_timeout":5,"health_workers":4}}`
	rec = srv.do(t, "POST", "/api/v1/import?mode=replace", doc)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400: %s", rec.Code, rec.Body)
	}

	after, _ := svc.Get()
	if len(after.AllowQuery) != len(before.AllowQuery) {
		t.Error("a rejected replace-mode import still changed the stored ACL")
	}
	got := srv.do(t, "GET", "/api/v1/services", "").Body.String()
	if !strings.Contains(got, "kypost") {
		t.Errorf("a rejected replace-mode import wiped the existing registry: %s", got)
	}
	if strings.Contains(got, "kept") {
		t.Errorf("a rejected replace-mode import still wrote the new services: %s", got)
	}
}

// The other half of the same guarantee: a valid settings block alongside an
// invalid registry payload must not leave the live server running someone
// else's settings while the request itself reports failure. Settings are
// checked, not applied, before ReplaceAll; they are only actually written
// after the registry replace (and the blacklist doc) have both succeeded.
func TestImportReplaceRejectsInvalidRegistryWithoutChangingSettings(t *testing.T) {
	srv, svc := testAPIWithSettings(t)
	before, _ := svc.Get()

	doc := `{"views":[],"services":[{"name":"bad name!!","addresses":[{"address":"192.168.1.30"}]}],
		"records":[],"settings":{
		"private_domain":"lab.arpa","reverse_zones":["192.168.1.0/24"],
		"upstreams":["udp://9.9.9.9:53"],"allow_query":["192.168.0.0/16"],
		"ttl":111,"cache_min_ttl":1,"cache_max_ttl":3600,"negative_max_ttl":60,
		"cache_entries":1000,"discovery_interval":60,"health_interval":30,
		"health_timeout":5,"health_workers":4}}`
	rec := srv.do(t, "POST", "/api/v1/import?mode=replace", doc)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400: %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "label_charset") {
		t.Errorf("body = %s, want the registry validation error", rec.Body)
	}

	after, _ := svc.Get()
	if after.TTL != before.TTL {
		t.Errorf("a rejected replace-mode import still changed the live TTL: %d, want %d", after.TTL, before.TTL)
	}
	if after.PrivateDomain != before.PrivateDomain {
		t.Errorf("a rejected replace-mode import still changed the live private_domain: %q, want %q",
			after.PrivateDomain, before.PrivateDomain)
	}
	if len(after.Upstreams) != 1 || after.Upstreams[0] != before.Upstreams[0] {
		t.Errorf("a rejected replace-mode import still changed the live upstreams: %v, want %v",
			after.Upstreams, before.Upstreams)
	}
}

// This is the end-to-end proof that the API's PATCH actually reaches a live
// component, not merely that Set returned nil: a real settings.Service is
// wired with an onApply that mirrors what Serve does for the ACL, and the
// test observes the running ACL change through the HTTP layer.
func TestPatchSettingsFansOutToTheLiveACL(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "kydns.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err := s.PutSettings(validStoredSettings()); err != nil {
		t.Fatal(err)
	}
	reg := registry.New(s, "home.arpa.", func() error { return nil })
	tok, err := reg.CreateToken("test")
	if err != nil {
		t.Fatal(err)
	}

	h := settings.NewHolder(func() (store.Settings, error) {
		v, _, err := s.Settings()
		return v, err
	})
	if err := h.Rebuild(); err != nil {
		t.Fatal(err)
	}

	acl := dnsserver.NewACL(h.Current().AllowQuery)
	svc := settings.NewService(s, h, func(snap *settings.Snapshot) {
		acl.Replace(snap.AllowQuery)
	})

	srv := &testSrv{h: NewAPI(reg, nil, nil).WithSettings(svc).Handler(), tok: tok}

	outside := netip.MustParseAddr("8.8.8.8")
	if acl.Allow(outside) {
		t.Fatal("test setup: 8.8.8.8 should not be allowed before the patch")
	}

	rec := srv.do(t, "PATCH", "/api/v1/settings",
		`{"allow_query":["192.168.0.0/16","0.0.0.0/0"],"confirm_public":"0.0.0.0/0"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}

	if !acl.Allow(outside) {
		t.Error("the live ACL did not observe the settings change: apply was not wired through the API")
	}
}
