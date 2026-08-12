package adminapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/yoshiofthewire/kydns-server/internal/policy"
	"github.com/yoshiofthewire/kydns-server/internal/registry"
	"github.com/yoshiofthewire/kydns-server/internal/store"
)

func newBlacklistAPI(t *testing.T) (http.Handler, string, *policy.Service) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "kydns.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	reg := registry.New(st, "home.arpa.", func() error { return nil })
	tok, err := reg.CreateToken("test")
	if err != nil {
		t.Fatal(err)
	}
	h := policy.NewHolder(func() (store.BlacklistSettings, []store.BlacklistList, []store.BlacklistRule, error) {
		set, err := st.BlacklistSettings()
		if err != nil {
			return set, nil, nil, err
		}
		lists, err := st.BlacklistLists()
		if err != nil {
			return set, nil, nil, err
		}
		rules, err := st.BlacklistRules()
		return set, lists, rules, err
	})
	if err := h.Rebuild(); err != nil {
		t.Fatal(err)
	}
	svc := policy.NewService(st, h, policy.NewRefresher(st, policy.NewFetcher(0), h, nil))
	api := NewAPI(reg, nil, nil).WithPolicy(svc)
	return api.Handler(), tok, svc
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode %s: %v", rec.Body, err)
	}
	return out
}

func TestBlacklistEndpointsRequireAToken(t *testing.T) {
	h, _, _ := newBlacklistAPI(t)
	for _, c := range []struct{ method, path string }{
		{"GET", "/api/v1/blacklists/settings"},
		{"PATCH", "/api/v1/blacklists/settings"},
		{"GET", "/api/v1/blacklists/lists"},
		{"POST", "/api/v1/blacklists/lists"},
		{"PATCH", "/api/v1/blacklists/lists/1"},
		{"DELETE", "/api/v1/blacklists/lists/1"},
		{"POST", "/api/v1/blacklists/lists/1/refresh"},
		{"GET", "/api/v1/blacklists/rules/deny"},
		{"POST", "/api/v1/blacklists/rules/deny"},
		{"DELETE", "/api/v1/blacklists/rules/deny/1"},
		{"GET", "/api/v1/blacklists/test?name=ads.example"},
	} {
		if rec := do(t, h, c.method, c.path, "", "{}"); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s without a token = %d, want 401", c.method, c.path, rec.Code)
		}
	}
}

func TestSettingsGetAndPatch(t *testing.T) {
	h, tok, _ := newBlacklistAPI(t)
	got := decodeBody(t, do(t, h, "GET", "/api/v1/blacklists/settings", tok, ""))
	if got["enabled"] != true || got["block_ttl"] != float64(60) {
		t.Errorf("GET settings = %v, want filtering on at 60s", got)
	}

	rec := do(t, h, "PATCH", "/api/v1/blacklists/settings", tok, `{"enabled":false}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PATCH = %d: %s", rec.Code, rec.Body)
	}
	got = decodeBody(t, do(t, h, "GET", "/api/v1/blacklists/settings", tok, ""))
	// An omitted field keeps its value, exactly like PATCH /services/{id}.
	if got["enabled"] != false || got["block_ttl"] != float64(60) {
		t.Errorf("after PATCH = %v, want {false 60}", got)
	}

	if rec := do(t, h, "PATCH", "/api/v1/blacklists/settings", tok, `{"block_ttl":99999}`); rec.Code != http.StatusBadRequest {
		t.Errorf("PATCH with an out-of-range TTL = %d, want 400", rec.Code)
	}
}

func TestListCRUD(t *testing.T) {
	h, tok, _ := newBlacklistAPI(t)
	rec := do(t, h, "POST", "/api/v1/blacklists/lists", tok,
		`{"name":"custom","url":"https://lists.example/hosts","format":"hosts","enabled":true,"interval_seconds":3600}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST = %d: %s", rec.Code, rec.Body)
	}
	id := int64(decodeBody(t, rec)["id"].(float64))

	listed := decodeBody(t, do(t, h, "GET", "/api/v1/blacklists/lists", tok, ""))
	lists, _ := listed["lists"].([]any)
	if len(lists) != 1 {
		t.Fatalf("GET lists = %v, want one entry", listed)
	}
	first, _ := lists[0].(map[string]any)
	if first["name"] != "custom" || first["entry_count"] != float64(0) {
		t.Errorf("list = %v, want the created definition", first)
	}
	// A list body is never in an API response.
	if _, leaked := first["snapshot"]; leaked {
		t.Error("the list response carries the downloaded body")
	}

	path := "/api/v1/blacklists/lists/" + strconv.FormatInt(id, 10)
	if rec := do(t, h, "PATCH", path, tok, `{"enabled":false}`); rec.Code != http.StatusOK {
		t.Errorf("PATCH = %d: %s", rec.Code, rec.Body)
	}
	if rec := do(t, h, "POST", "/api/v1/blacklists/lists", tok, `{"name":"bad","url":"http://x/y"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("POST with a plain-http URL = %d, want 400", rec.Code)
	}
	if rec := do(t, h, "DELETE", path, tok, ""); rec.Code != http.StatusNoContent {
		t.Errorf("DELETE = %d, want 204", rec.Code)
	}
	if rec := do(t, h, "DELETE", path, tok, ""); rec.Code != http.StatusNotFound {
		t.Errorf("second DELETE = %d, want 404", rec.Code)
	}
}

func TestRuleCRUDAndConflict(t *testing.T) {
	h, tok, _ := newBlacklistAPI(t)
	if rec := do(t, h, "POST", "/api/v1/blacklists/rules/deny", tok, `{"domain":"Ads.Example."}`); rec.Code != http.StatusCreated {
		t.Fatalf("POST deny = %d: %s", rec.Code, rec.Body)
	}
	got := decodeBody(t, do(t, h, "GET", "/api/v1/blacklists/rules/deny", tok, ""))
	rules, _ := got["rules"].([]any)
	if len(rules) != 1 {
		t.Fatalf("GET deny rules = %v, want one", got)
	}
	if r, _ := rules[0].(map[string]any); r["domain"] != "ads.example" {
		t.Errorf("rule = %v, want the normalized domain", rules[0])
	}
	// The allow list is a separate collection.
	empty := decodeBody(t, do(t, h, "GET", "/api/v1/blacklists/rules/allow", tok, ""))
	if a, _ := empty["rules"].([]any); len(a) != 0 {
		t.Errorf("GET allow rules = %v, want empty", empty)
	}
	if rec := do(t, h, "POST", "/api/v1/blacklists/rules/allow", tok, `{"domain":"ads.example"}`); rec.Code != http.StatusConflict {
		t.Errorf("conflicting rule = %d, want 409", rec.Code)
	}
	if rec := do(t, h, "POST", "/api/v1/blacklists/rules/deny", tok, `{"domain":"not a domain"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("malformed domain = %d, want 400", rec.Code)
	}
	if rec := do(t, h, "DELETE", "/api/v1/blacklists/rules/deny/1", tok, ""); rec.Code != http.StatusNoContent {
		t.Errorf("DELETE = %d, want 204", rec.Code)
	}
}

func TestTestEndpointReportsTheDecision(t *testing.T) {
	h, tok, _ := newBlacklistAPI(t)
	if rec := do(t, h, "POST", "/api/v1/blacklists/rules/deny", tok, `{"domain":"ads.example"}`); rec.Code != http.StatusCreated {
		t.Fatal(rec.Body)
	}
	got := decodeBody(t, do(t, h, "GET", "/api/v1/blacklists/test?name=cdn.ads.example", tok, ""))
	if got["blocked"] != true || got["policy"] != "deny" {
		t.Errorf("test = %v, want blocked by deny", got)
	}
	got = decodeBody(t, do(t, h, "GET", "/api/v1/blacklists/test?name=example.org", tok, ""))
	if got["blocked"] != false || got["policy"] != "forwarded" {
		t.Errorf("test = %v, want forwarded", got)
	}
	if rec := do(t, h, "GET", "/api/v1/blacklists/test?name=", tok, ""); rec.Code != http.StatusBadRequest {
		t.Errorf("test with no name = %d, want 400", rec.Code)
	}
}

// With no policy wired the endpoints answer cleanly rather than panicking.
func TestBlacklistEndpointsWithoutAPolicy(t *testing.T) {
	h, tok := newAPI(t)
	if rec := do(t, h, "GET", "/api/v1/blacklists/settings", tok, ""); rec.Code != http.StatusNotFound {
		t.Errorf("= %d, want 404 when filtering is not wired", rec.Code)
	}
}
