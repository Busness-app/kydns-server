package adminapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yoshiofthewire/kydns-server/internal/registry"
	"github.com/yoshiofthewire/kydns-server/internal/store"
)

func newAPI(t *testing.T) (http.Handler, string) {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "kydns.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	reg := registry.New(s, "home.arpa.", func() error { return nil })
	tok, err := reg.CreateToken("test")
	if err != nil {
		t.Fatal(err)
	}
	return NewAPI(reg, nil, nil).Handler(), tok
}

func do(t *testing.T, h http.Handler, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestUnauthenticatedRejected(t *testing.T) {
	h, _ := newAPI(t)
	for _, path := range []string{"/api/v1/services", "/api/v1/records", "/api/v1/views", "/api/v1/tokens"} {
		if rec := do(t, h, "GET", path, "", ""); rec.Code != http.StatusUnauthorized {
			t.Errorf("GET %s without a token = %d, want 401", path, rec.Code)
		}
	}
}

func TestBadTokenRejected(t *testing.T) {
	h, _ := newAPI(t)
	if rec := do(t, h, "GET", "/api/v1/services", "kydns_bogus", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("= %d, want 401", rec.Code)
	}
}

func TestHealthzIsUnauthenticated(t *testing.T) {
	h, _ := newAPI(t)
	if rec := do(t, h, "GET", "/api/v1/healthz", "", ""); rec.Code != http.StatusOK {
		t.Errorf("GET /healthz = %d, want 200", rec.Code)
	}
}

func TestCreateAndListService(t *testing.T) {
	h, tok := newAPI(t)
	rec := do(t, h, "POST", "/api/v1/services", tok,
		`{"name":"kypost","addresses":[{"address":"192.168.1.20"}],"aliases":["webmail"]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /services = %d: %s", rec.Code, rec.Body)
	}
	rec = do(t, h, "GET", "/api/v1/services", tok, "")
	var got struct {
		Services []struct {
			Name      string `json:"name"`
			Addresses []struct {
				Address string `json:"address"`
				View    string `json:"view"`
			} `json:"addresses"`
		} `json:"services"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Services) != 1 || got.Services[0].Name != "kypost" {
		t.Fatalf("GET /services = %s", rec.Body)
	}
}

func TestValidationErrorNamesTheField(t *testing.T) {
	h, tok := newAPI(t)
	rec := do(t, h, "POST", "/api/v1/services", tok, `{"name":"bad_name","addresses":[{"address":"192.168.1.20"}]}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("= %d, want 400: %s", rec.Code, rec.Body)
	}
	var e struct {
		Error struct{ Code, Message, Field string } `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil {
		t.Fatal(err)
	}
	if e.Error.Field != "name" || e.Error.Code == "" {
		t.Errorf("error body = %s, want a field and a code", rec.Body)
	}
}

func TestMalformedJSONIs400(t *testing.T) {
	h, tok := newAPI(t)
	if rec := do(t, h, "POST", "/api/v1/services", tok, `{not json`); rec.Code != http.StatusBadRequest {
		t.Errorf("= %d, want 400", rec.Code)
	}
}

func TestDuplicateNameIs409(t *testing.T) {
	h, tok := newAPI(t)
	body := `{"name":"kypost","addresses":[{"address":"192.168.1.20"}]}`
	do(t, h, "POST", "/api/v1/services", tok, body)
	if rec := do(t, h, "POST", "/api/v1/services", tok, body); rec.Code != http.StatusConflict {
		t.Errorf("duplicate POST = %d, want 409", rec.Code)
	}
}

func TestDeleteViewInUseIs409(t *testing.T) {
	h, tok := newAPI(t)
	do(t, h, "POST", "/api/v1/views", tok, `{"name":"tailnet","subnets":["100.64.0.0/10"]}`)
	do(t, h, "POST", "/api/v1/services", tok,
		`{"name":"kypost","addresses":[{"address":"100.101.102.103","view":"tailnet"}]}`)
	if rec := do(t, h, "DELETE", "/api/v1/views/tailnet", tok, ""); rec.Code != http.StatusConflict {
		t.Errorf("DELETE in-use view = %d, want 409", rec.Code)
	}
}

func TestUnknownServiceIs404(t *testing.T) {
	h, tok := newAPI(t)
	if rec := do(t, h, "DELETE", "/api/v1/services/999", tok, ""); rec.Code != http.StatusNotFound {
		t.Errorf("= %d, want 404", rec.Code)
	}
}

func TestServiceDelete(t *testing.T) {
	h, tok := newAPI(t)
	do(t, h, "POST", "/api/v1/services", tok, `{"name":"gone","addresses":[{"address":"192.168.1.40"}]}`)
	var listed struct {
		Services []struct {
			ID int64 `json:"id"`
		} `json:"services"`
	}
	json.Unmarshal(do(t, h, "GET", "/api/v1/services", tok, "").Body.Bytes(), &listed)
	if len(listed.Services) != 1 {
		t.Fatal("service not created")
	}
	path := "/api/v1/services/" + itoa(listed.Services[0].ID)
	if rec := do(t, h, "DELETE", path, tok, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE = %d: %s", rec.Code, rec.Body)
	}
	if bytes.Contains(do(t, h, "GET", "/api/v1/services", tok, "").Body.Bytes(), []byte("gone")) {
		t.Error("deleted service still listed")
	}
}

func TestGetServiceByID(t *testing.T) {
	h, tok := newAPI(t)
	do(t, h, "POST", "/api/v1/services", tok, `{"name":"kypost","addresses":[{"address":"192.168.1.20"}]}`)
	rec := do(t, h, "GET", "/api/v1/services/1", tok, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("= %d: %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "kypost") {
		t.Errorf("body = %s", rec.Body)
	}
	if rec := do(t, h, "GET", "/api/v1/services/999", tok, ""); rec.Code != http.StatusNotFound {
		t.Errorf("unknown id = %d, want 404", rec.Code)
	}
}

// The Tailscale workflow: a service already exists, and the operator adds a
// tailnet-tagged address to it without deleting and recreating it.
func TestPatchServiceAddsViewTaggedAddress(t *testing.T) {
	h, tok := newAPI(t)
	do(t, h, "POST", "/api/v1/views", tok, `{"name":"tailnet","subnets":["100.64.0.0/10"]}`)
	do(t, h, "POST", "/api/v1/services", tok, `{"name":"kypost","addresses":[{"address":"192.168.1.20"}]}`)

	rec := do(t, h, "PATCH", "/api/v1/services/1", tok,
		`{"name":"kypost","addresses":[{"address":"192.168.1.20"},{"address":"100.101.102.103","view":"tailnet"}]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PATCH = %d: %s", rec.Code, rec.Body)
	}
	body := do(t, h, "GET", "/api/v1/services/1", tok, "").Body.String()
	if !strings.Contains(body, "100.101.102.103") || !strings.Contains(body, "tailnet") {
		t.Errorf("patched service = %s, want both addresses", body)
	}
	if !strings.Contains(body, "192.168.1.20") {
		t.Errorf("patch dropped the original address: %s", body)
	}
	// The update must replace children, not accumulate duplicates.
	if n := strings.Count(body, "192.168.1.20"); n != 1 {
		t.Errorf("original address appears %d times, want 1", n)
	}
}

func TestPatchUnknownServiceIs404(t *testing.T) {
	h, tok := newAPI(t)
	rec := do(t, h, "PATCH", "/api/v1/services/999", tok,
		`{"name":"ghost","addresses":[{"address":"192.168.1.1"}]}`)
	if rec.Code != http.StatusNotFound {
		t.Errorf("= %d, want 404", rec.Code)
	}
}

// A PATCH that omits fields must not clear them: the whole reason PATCH
// exists instead of PUT.
func TestPatchOmittedFieldsSurvive(t *testing.T) {
	h, tok := newAPI(t)
	do(t, h, "POST", "/api/v1/services", tok,
		`{"name":"grafana","addresses":[{"address":"192.168.1.20"}],"aliases":["metrics"],
		  "check_url":"https://grafana.home.arpa/health","check_insecure":true,
		  "proxy_address":"192.168.1.20","route_via_proxy":true}`)

	rec := do(t, h, "PATCH", "/api/v1/services/1", tok, `{"name":"grafana","addresses":[{"address":"192.168.1.60"}]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PATCH = %d: %s", rec.Code, rec.Body)
	}

	rec = do(t, h, "GET", "/api/v1/services/1", tok, "")
	var got serviceDTO
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Aliases) != 1 || got.Aliases[0] != "metrics" {
		t.Errorf("aliases = %v, want [metrics] preserved", got.Aliases)
	}
	if got.CheckURL != "https://grafana.home.arpa/health" {
		t.Errorf("check_url = %q, want preserved", got.CheckURL)
	}
	if !got.CheckInsecure {
		t.Error("check_insecure was cleared")
	}
	if got.ProxyAddress != "192.168.1.20" {
		t.Errorf("proxy_address = %q, want preserved", got.ProxyAddress)
	}
	if !got.RouteViaProxy {
		t.Error("route_via_proxy was cleared by an omitted key")
	}
	if len(got.Addresses) != 1 || got.Addresses[0].Address != "192.168.1.60" {
		t.Errorf("addresses = %+v, want the new address applied", got.Addresses)
	}
}

// A provided addresses array replaces the slice wholesale. encoding/json
// merges into existing slice elements by default, which would leak the old
// address's view tag onto the new address.
func TestPatchAddressesReplaceNotMerge(t *testing.T) {
	h, tok := newAPI(t)
	do(t, h, "POST", "/api/v1/views", tok, `{"name":"vpn","subnets":["100.64.0.0/10"]}`)
	do(t, h, "POST", "/api/v1/services", tok,
		`{"name":"kypost","addresses":[{"address":"10.0.0.5","view":"vpn"}]}`)

	rec := do(t, h, "PATCH", "/api/v1/services/1", tok, `{"addresses":[{"address":"192.168.1.60"}]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PATCH = %d: %s", rec.Code, rec.Body)
	}

	rec = do(t, h, "GET", "/api/v1/services/1", tok, "")
	var got serviceDTO
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Addresses) != 1 {
		t.Fatalf("addresses = %+v, want exactly one", got.Addresses)
	}
	if got.Addresses[0].Address != "192.168.1.60" {
		t.Errorf("address = %q, want 192.168.1.60", got.Addresses[0].Address)
	}
	if got.Addresses[0].View != "" {
		t.Errorf("view = %q, the old address's view leaked onto the new one", got.Addresses[0].View)
	}
}

// encoding/json matches struct fields case-insensitively, so presence
// detection for "addresses" must not use an exact map lookup or a
// differently-cased key sails past the reset and merges into the old slice.
func TestPatchAddressesReplaceNotMergeCaseInsensitiveKey(t *testing.T) {
	h, tok := newAPI(t)
	do(t, h, "POST", "/api/v1/views", tok, `{"name":"vpn","subnets":["100.64.0.0/10"]}`)
	do(t, h, "POST", "/api/v1/services", tok,
		`{"name":"kypost","addresses":[{"address":"10.0.0.5","view":"vpn"}]}`)

	rec := do(t, h, "PATCH", "/api/v1/services/1", tok, `{"Addresses":[{"address":"192.168.1.60"}]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PATCH = %d: %s", rec.Code, rec.Body)
	}

	rec = do(t, h, "GET", "/api/v1/services/1", tok, "")
	var got serviceDTO
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Addresses) != 1 {
		t.Fatalf("addresses = %+v, want exactly one", got.Addresses)
	}
	if got.Addresses[0].View != "" {
		t.Errorf("view = %q, a differently-cased key let the old view leak onto the new address", got.Addresses[0].View)
	}
}

// "aliases": [] must explicitly clear the aliases, not be treated as absent.
func TestPatchEmptyAliasesClears(t *testing.T) {
	h, tok := newAPI(t)
	do(t, h, "POST", "/api/v1/services", tok,
		`{"name":"kypost","addresses":[{"address":"192.168.1.20"}],"aliases":["webmail"]}`)

	rec := do(t, h, "PATCH", "/api/v1/services/1", tok, `{"aliases":[]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PATCH = %d: %s", rec.Code, rec.Body)
	}

	rec = do(t, h, "GET", "/api/v1/services/1", tok, "")
	var got serviceDTO
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Aliases) != 0 {
		t.Errorf("aliases = %v, want cleared", got.Aliases)
	}
}

// "check_url": "" must explicitly clear the field.
func TestPatchEmptyCheckURLClears(t *testing.T) {
	h, tok := newAPI(t)
	do(t, h, "POST", "/api/v1/services", tok,
		`{"name":"kypost","addresses":[{"address":"192.168.1.20"}],"check_url":"https://kypost.home.arpa/health"}`)

	rec := do(t, h, "PATCH", "/api/v1/services/1", tok, `{"check_url":""}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PATCH = %d: %s", rec.Code, rec.Body)
	}

	rec = do(t, h, "GET", "/api/v1/services/1", tok, "")
	var got serviceDTO
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.CheckURL != "" {
		t.Errorf("check_url = %q, want cleared", got.CheckURL)
	}
}

func TestPatchValidates(t *testing.T) {
	h, tok := newAPI(t)
	do(t, h, "POST", "/api/v1/services", tok, `{"name":"kypost","addresses":[{"address":"192.168.1.20"}]}`)
	rec := do(t, h, "PATCH", "/api/v1/services/1", tok, `{"name":"kypost","addresses":[{"address":"nope"}]}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("= %d, want 400 for an invalid address", rec.Code)
	}
}

// Export must never leak secrets. This is a stated security requirement.
func TestExportOmitsSecrets(t *testing.T) {
	h, tok := newAPI(t)
	do(t, h, "POST", "/api/v1/services", tok, `{"name":"kypost","addresses":[{"address":"192.168.1.20"}]}`)
	rec := do(t, h, "GET", "/api/v1/export?format=yaml", tok, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("= %d: %s", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	for _, forbidden := range []string{tok, "hash", "token", "password", "argon2"} {
		if strings.Contains(strings.ToLower(body), strings.ToLower(forbidden)) {
			t.Errorf("export contains %q:\n%s", forbidden, body)
		}
	}
	if !strings.Contains(body, "kypost") {
		t.Errorf("export is missing the service:\n%s", body)
	}
}

func TestExportJSON(t *testing.T) {
	h, tok := newAPI(t)
	do(t, h, "POST", "/api/v1/services", tok, `{"name":"kypost","addresses":[{"address":"192.168.1.20"}]}`)
	rec := do(t, h, "GET", "/api/v1/export?format=json", tok, "")
	var doc struct {
		Services []struct{ Name string } `json:"services"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("json export is not valid JSON: %v\n%s", err, rec.Body)
	}
	if len(doc.Services) != 1 {
		t.Errorf("services = %+v", doc.Services)
	}
}

func TestImportReplace(t *testing.T) {
	h, tok := newAPI(t)
	do(t, h, "POST", "/api/v1/services", tok, `{"name":"old","addresses":[{"address":"192.168.1.9"}]}`)
	body := `{"views":[],"services":[{"name":"fresh","addresses":[{"address":"192.168.1.10"}]}],"records":[]}`
	if rec := do(t, h, "POST", "/api/v1/import?mode=replace", tok, body); rec.Code != http.StatusOK {
		t.Fatalf("import = %d: %s", rec.Code, rec.Body)
	}
	rec := do(t, h, "GET", "/api/v1/services", tok, "")
	if strings.Contains(rec.Body.String(), "old") {
		t.Errorf("replace left the old service behind: %s", rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "fresh") {
		t.Errorf("replace did not add the new service: %s", rec.Body)
	}
}

// An import must never revoke the operator's own token.
func TestImportReplaceKeepsTokens(t *testing.T) {
	h, tok := newAPI(t)
	body := `{"views":[],"services":[],"records":[]}`
	if rec := do(t, h, "POST", "/api/v1/import?mode=replace", tok, body); rec.Code != http.StatusOK {
		t.Fatalf("import = %d: %s", rec.Code, rec.Body)
	}
	if rec := do(t, h, "GET", "/api/v1/services", tok, ""); rec.Code != http.StatusOK {
		t.Errorf("token stopped working after import --replace: %d", rec.Code)
	}
}

func TestImportMerge(t *testing.T) {
	h, tok := newAPI(t)
	do(t, h, "POST", "/api/v1/services", tok, `{"name":"keep","addresses":[{"address":"192.168.1.9"}]}`)
	body := `{"services":[{"name":"added","addresses":[{"address":"192.168.1.10"}]}]}`
	if rec := do(t, h, "POST", "/api/v1/import?mode=merge", tok, body); rec.Code != http.StatusOK {
		t.Fatalf("import = %d: %s", rec.Code, rec.Body)
	}
	got := do(t, h, "GET", "/api/v1/services", tok, "").Body.String()
	if !strings.Contains(got, "keep") || !strings.Contains(got, "added") {
		t.Errorf("merge lost data: %s", got)
	}
}

// A round trip through export and import --replace must preserve view tags.
func TestExportImportRoundTripPreservesViews(t *testing.T) {
	h, tok := newAPI(t)
	do(t, h, "POST", "/api/v1/views", tok, `{"name":"tailnet","subnets":["100.64.0.0/10"]}`)
	do(t, h, "POST", "/api/v1/services", tok,
		`{"name":"kypost","addresses":[{"address":"192.168.1.20"},{"address":"100.101.102.103","view":"tailnet"}]}`)

	exported := do(t, h, "GET", "/api/v1/export?format=json", tok, "").Body.String()
	if rec := do(t, h, "POST", "/api/v1/import?mode=replace", tok, exported); rec.Code != http.StatusOK {
		t.Fatalf("re-import = %d: %s", rec.Code, rec.Body)
	}
	got := do(t, h, "GET", "/api/v1/services", tok, "").Body.String()
	if !strings.Contains(got, "tailnet") || !strings.Contains(got, "100.101.102.103") {
		t.Errorf("round trip lost the view tag: %s", got)
	}
}

func TestServiceProxyFieldsRoundTripThroughTheAPI(t *testing.T) {
	h, tok := newAPI(t)

	do(t, h, "POST", "/api/v1/services", tok,
		`{"name":"kypost","addresses":[{"address":"192.168.1.30"}],
		  "proxy_address":"192.168.1.20","route_via_proxy":true}`)

	rec := do(t, h, "GET", "/api/v1/services", tok, "")
	var got struct {
		Services []struct {
			Name          string `json:"name"`
			ProxyAddress  string `json:"proxy_address"`
			RouteViaProxy bool   `json:"route_via_proxy"`
		} `json:"services"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Services) != 1 {
		t.Fatalf("services = %d, want 1", len(got.Services))
	}
	if got.Services[0].ProxyAddress != "192.168.1.20" || !got.Services[0].RouteViaProxy {
		t.Errorf("= %+v, want the proxy fields", got.Services[0])
	}

	// Export must carry them, or a backup silently loses the routing.
	rec = do(t, h, "GET", "/api/v1/export?format=yaml", tok, "")
	for _, want := range []string{"proxy_address", "route_via_proxy"} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("export does not contain %q", want)
		}
	}
}

// A replace-mode import must not bypass the same validation PutService
// applies one at a time.
// A rejected replace must leave pre-existing data alone, not wipe it and
// half-restore. The store started empty would only catch the bad service
// being written, not the registry being wiped out from under it.
func TestImportReplaceRejectsRoutedServiceWithoutProxyAddress(t *testing.T) {
	h, tok := newAPI(t)
	do(t, h, "POST", "/api/v1/services", tok, `{"name":"keeper","addresses":[{"address":"192.168.1.9"}]}`)

	body := `{"views":[],"services":[{"name":"kypost","addresses":[{"address":"192.168.1.30"}],
	  "route_via_proxy":true}],"records":[]}`
	rec := do(t, h, "POST", "/api/v1/import?mode=replace", tok, body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("import = %d, want 400: %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "proxy_address_required") {
		t.Errorf("body = %s, want proxy_address_required", rec.Body)
	}

	got := do(t, h, "GET", "/api/v1/services", tok, "").Body.String()
	if strings.Contains(got, "kypost") {
		t.Errorf("rejected import still wrote the service: %s", got)
	}
	if !strings.Contains(got, "keeper") {
		t.Errorf("rejected import wiped pre-existing data: %s", got)
	}
}

// A validly routed service must still round-trip through replace.
func TestImportReplaceAcceptsRoutedServiceWithProxyAddress(t *testing.T) {
	h, tok := newAPI(t)
	body := `{"views":[],"services":[{"name":"kypost","addresses":[{"address":"192.168.1.30"}],
	  "proxy_address":"192.168.1.20","route_via_proxy":true}],"records":[]}`
	if rec := do(t, h, "POST", "/api/v1/import?mode=replace", tok, body); rec.Code != http.StatusOK {
		t.Fatalf("import = %d: %s", rec.Code, rec.Body)
	}

	rec := do(t, h, "GET", "/api/v1/services", tok, "")
	var got struct {
		Services []struct {
			Name          string `json:"name"`
			ProxyAddress  string `json:"proxy_address"`
			RouteViaProxy bool   `json:"route_via_proxy"`
		} `json:"services"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Services) != 1 || got.Services[0].ProxyAddress != "192.168.1.20" || !got.Services[0].RouteViaProxy {
		t.Errorf("= %+v, want the routed service to survive replace", got.Services)
	}
}

func TestTokensEndpointNeverReturnsPlaintext(t *testing.T) {
	h, tok := newAPI(t)
	rec := do(t, h, "POST", "/api/v1/tokens", tok, `{"label":"second"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("= %d: %s", rec.Code, rec.Body)
	}
	var created struct {
		Token string `json:"token"`
	}
	json.Unmarshal(rec.Body.Bytes(), &created)
	if created.Token == "" {
		t.Fatal("creation response must include the plaintext once")
	}
	rec = do(t, h, "GET", "/api/v1/tokens", tok, "")
	if bytes.Contains(rec.Body.Bytes(), []byte(created.Token)) {
		t.Error("GET /tokens leaked a plaintext token")
	}
	if bytes.Contains(rec.Body.Bytes(), []byte("hash")) {
		t.Error("GET /tokens exposed the stored hash")
	}
}

func TestStatsEndpoint(t *testing.T) {
	h, tok := newAPI(t)
	if rec := do(t, h, "GET", "/api/v1/stats", tok, ""); rec.Code != http.StatusOK {
		t.Errorf("= %d: %s", rec.Code, rec.Body)
	}
}

func itoa(i int64) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
