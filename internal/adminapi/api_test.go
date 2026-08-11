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
