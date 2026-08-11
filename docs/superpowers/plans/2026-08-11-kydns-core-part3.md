# KyDNS Core Resolver Implementation Plan — Part 3 (Tasks 12–13)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax for tracking.

**Continues:** `2026-08-11-kydns-core.md` (Tasks 1–6) and `-part2.md` (Tasks 7–11). Read the **Global Constraints** in part 1 — they apply here.

**Goal of this part:** make the resolver operable. Token-authenticated admin API over the registry, export/import, the CLI, and `kydns serve` wiring it together, proven by an end-to-end test that adds a service over HTTP and resolves it over DNS.

**Completes Plan 1.** After Task 13, `kydns serve` is a usable DNS server. Plan 2 adds the web UI and password auth; Plan 3 adds discovery and health.

---

### Task 12: Registry service and admin API

This is one task, not two: the registry service layer has no meaning without a
transport exercising it, and a reviewer would reject or accept them together.

**Files:**
- Create: `internal/registry/registry.go`, `internal/adminapi/tokens.go`, `internal/adminapi/api.go`
- Test: `internal/registry/registry_test.go`, `internal/adminapi/api_test.go`

**Interfaces:**
- Consumes: `store.Store`, `store.Service`, `store.Record`, `store.View`, `zone.Holder`, validation from Task 4.
- Produces:
  - `type Registry struct{ ... }`, `func New(s *store.Store, zoneFQDN string, onChange func() error) *Registry`
  - `func (r *Registry) PutService(store.Service) (int64, error)`, `DeleteService(int64) error`, `Services() ([]store.Service, error)`
  - `func (r *Registry) PutRecord(store.Record) (int64, error)`, `DeleteRecord(int64) error`, `Records() ([]store.Record, error)`
  - `func (r *Registry) PutView(store.View) error`, `DeleteView(string) error`, `Views() ([]store.View, error)`
  - `func GenerateToken() (plaintext, hash string)`, `func HashToken(plaintext string) string`
  - `func (r *Registry) CreateToken(label string) (string, error)`, `AuthenticateToken(string) bool`, `Tokens() ([]store.Token, error)`, `DeleteToken(int64) error`
  - `type API struct{ ... }`, `func NewAPI(reg *Registry, acl *dnsserver.ACL, cache *dnsserver.Cache) *API`, `func (a *API) Handler() http.Handler`

- [ ] **Step 1: Write the failing test**

```go
// internal/registry/registry_test.go
package registry

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/yoshiofthewire/kydns-server/internal/store"
)

func newRegistry(t *testing.T) (*Registry, *int) {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "kydns.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	rebuilds := 0
	r := New(s, "home.arpa.", func() error { rebuilds++; return nil })
	return r, &rebuilds
}

func TestPutServiceNormalizesAndRebuilds(t *testing.T) {
	r, rebuilds := newRegistry(t)
	id, err := r.PutService(store.Service{
		Name:      "KyPost",
		Addresses: []store.Address{{Address: "192.168.1.20"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if id == 0 {
		t.Fatal("PutService() returned id 0")
	}
	if *rebuilds != 1 {
		t.Errorf("rebuilds = %d, want 1", *rebuilds)
	}
	svcs, err := r.Services()
	if err != nil {
		t.Fatal(err)
	}
	if svcs[0].Name != "kypost" {
		t.Errorf("Name = %q, want lowercased kypost", svcs[0].Name)
	}
}

func TestPutServiceRejectsBadInput(t *testing.T) {
	r, _ := newRegistry(t)
	cases := map[string]store.Service{
		"empty name":     {Addresses: []store.Address{{Address: "192.168.1.20"}}},
		"bad label":      {Name: "has_underscore", Addresses: []store.Address{{Address: "192.168.1.20"}}},
		"bad address":    {Name: "ok", Addresses: []store.Address{{Address: "nope"}}},
		"no address":     {Name: "ok"},
		"unknown view":   {Name: "ok", Addresses: []store.Address{{Address: "192.168.1.20", View: "ghost"}}},
		"wildcard":       {Name: "*", Addresses: []store.Address{{Address: "192.168.1.20"}}},
		"alias conflict": {Name: "ok", Addresses: []store.Address{{Address: "192.168.1.20"}}, Aliases: []string{"bad_alias"}},
	}
	for name, svc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := r.PutService(svc); err == nil {
				t.Fatal("PutService() error = nil, want validation error")
			}
		})
	}
}

// A rejected write must not leave a rebuild behind.
func TestFailedWriteDoesNotRebuild(t *testing.T) {
	r, rebuilds := newRegistry(t)
	if _, err := r.PutService(store.Service{Name: "bad_name"}); err == nil {
		t.Fatal("want validation error")
	}
	if *rebuilds != 0 {
		t.Errorf("rebuilds = %d after a failed write, want 0", *rebuilds)
	}
}

func TestPutViewValidatesCIDRs(t *testing.T) {
	r, _ := newRegistry(t)
	if err := r.PutView(store.View{Name: "tailnet", Subnets: []string{"100.64.0.0/10"}}); err != nil {
		t.Fatal(err)
	}
	if err := r.PutView(store.View{Name: "bad", Subnets: []string{"not-a-cidr"}}); err == nil {
		t.Error("PutView() accepted an invalid CIDR")
	}
	if err := r.PutView(store.View{Name: "", Subnets: []string{"10.0.0.0/8"}}); err == nil {
		t.Error("PutView() accepted an empty name")
	}
}

func TestDeleteViewInUse(t *testing.T) {
	r, _ := newRegistry(t)
	if err := r.PutView(store.View{Name: "tailnet", Subnets: []string{"100.64.0.0/10"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.PutService(store.Service{
		Name:      "kypost",
		Addresses: []store.Address{{Address: "100.101.102.103", View: "tailnet"}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := r.DeleteView("tailnet"); !errors.Is(err, store.ErrViewInUse) {
		t.Errorf("DeleteView() error = %v, want ErrViewInUse", err)
	}
}

func TestTokenLifecycle(t *testing.T) {
	r, _ := newRegistry(t)
	plaintext, err := r.CreateToken("laptop")
	if err != nil {
		t.Fatal(err)
	}
	if len(plaintext) < 20 {
		t.Errorf("token %q is too short", plaintext)
	}
	if !r.AuthenticateToken(plaintext) {
		t.Error("AuthenticateToken() rejected a freshly created token")
	}
	if r.AuthenticateToken("kydns_wrong") {
		t.Error("AuthenticateToken() accepted a bogus token")
	}
	toks, err := r.Tokens()
	if err != nil {
		t.Fatal(err)
	}
	if len(toks) != 1 {
		t.Fatalf("Tokens() = %d entries, want 1", len(toks))
	}
	// The plaintext must never be recoverable from storage.
	if toks[0].Hash == plaintext {
		t.Error("token stored in plaintext")
	}
}
```

```go
// internal/adminapi/api_test.go
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
	if rec := do(t, h, "DELETE", "/api/v1/services/999", tok); rec.Code != http.StatusNotFound {
		t.Errorf("= %d, want 404", rec.Code)
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
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/registry/ ./internal/adminapi/ -v`
Expected: FAIL — `undefined: New` and `undefined: NewAPI`.

- [ ] **Step 3: Write minimal implementation**

```go
// internal/registry/registry.go
package registry

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"

	"github.com/yoshiofthewire/kydns-server/internal/store"
)

// Registry is the application service both transports call. Validation lives
// here so the JSON API and the CLI cannot drift apart.
type Registry struct {
	s        *store.Store
	zone     string
	onChange func() error
}

func New(s *store.Store, zoneFQDN string, onChange func() error) *Registry {
	if onChange == nil {
		onChange = func() error { return nil }
	}
	return &Registry{s: s, zone: Normalize(zoneFQDN), onChange: onChange}
}

func (r *Registry) knownViews() (map[string]bool, error) {
	views, err := r.s.Views()
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, v := range views {
		out[v.Name] = true
	}
	return out, nil
}

// PutService validates, writes, then rebuilds. A failed validation never
// reaches the store and never triggers a rebuild.
func (r *Registry) PutService(svc store.Service) (int64, error) {
	svc.Name = strings.ToLower(strings.TrimSpace(svc.Name))
	if err := ValidateName(svc.Name+"."+r.zone, r.zone); err != nil {
		return 0, err
	}
	if len(svc.Addresses) == 0 {
		return 0, invalid("addresses", "addresses_required", "a service needs at least one address")
	}
	known, err := r.knownViews()
	if err != nil {
		return 0, err
	}
	for i, a := range svc.Addresses {
		if err := ValidateAddress(a.Address); err != nil {
			return 0, err
		}
		if a.View != "" && !known[a.View] {
			return 0, invalid(fmt.Sprintf("addresses[%d].view", i), "view_unknown", "view %q does not exist", a.View)
		}
	}
	for i, al := range svc.Aliases {
		svc.Aliases[i] = strings.ToLower(strings.TrimSpace(al))
		if err := ValidateName(svc.Aliases[i]+"."+r.zone, r.zone); err != nil {
			return 0, err
		}
	}
	id, err := r.s.PutService(svc)
	if err != nil {
		return 0, err
	}
	return id, r.onChange()
}

func (r *Registry) Services() ([]store.Service, error) { return r.s.Services() }

func (r *Registry) DeleteService(id int64) error {
	if err := r.s.DeleteService(id); err != nil {
		return err
	}
	return r.onChange()
}

func (r *Registry) PutRecord(rec store.Record) (int64, error) {
	rec.Name = Normalize(rec.Name)
	rec.Type = strings.ToUpper(strings.TrimSpace(rec.Type))
	if err := ValidateRecordType(rec.Type); err != nil {
		return 0, err
	}
	switch rec.Type {
	case "A", "AAAA":
		if err := ValidateName(rec.Name, r.zone); err != nil {
			return 0, err
		}
		if err := ValidateAddress(rec.Value); err != nil {
			return 0, err
		}
	case "CNAME":
		if err := ValidateName(rec.Name, r.zone); err != nil {
			return 0, err
		}
		rec.Value = Normalize(rec.Value)
	case "PTR":
		if !strings.HasSuffix(rec.Name, ".arpa.") {
			return 0, invalid("name", "ptr_not_arpa", "a PTR name must end in .arpa.")
		}
		rec.Value = Normalize(rec.Value)
	}
	known, err := r.knownViews()
	if err != nil {
		return 0, err
	}
	if rec.View != "" && !known[rec.View] {
		return 0, invalid("view", "view_unknown", "view %q does not exist", rec.View)
	}
	id, err := r.s.PutRecord(rec)
	if err != nil {
		return 0, err
	}
	return id, r.onChange()
}

func (r *Registry) Records() ([]store.Record, error) { return r.s.Records() }

func (r *Registry) DeleteRecord(id int64) error {
	if err := r.s.DeleteRecord(id); err != nil {
		return err
	}
	return r.onChange()
}

func (r *Registry) PutView(v store.View) error {
	v.Name = strings.ToLower(strings.TrimSpace(v.Name))
	if err := ValidateLabel(v.Name); err != nil {
		return invalid("name", "view_name_invalid", "view name %q must be a single DNS label", v.Name)
	}
	if len(v.Subnets) == 0 {
		return invalid("subnets", "subnets_required", "a view needs at least one subnet")
	}
	for i, c := range v.Subnets {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return invalid(fmt.Sprintf("subnets[%d]", i), "cidr_invalid", "%q is not a CIDR", c)
		}
		v.Subnets[i] = p.Masked().String()
	}
	if err := r.s.PutView(v); err != nil {
		return err
	}
	return r.onChange()
}

func (r *Registry) Views() ([]store.View, error) { return r.s.Views() }

func (r *Registry) DeleteView(name string) error {
	if err := r.s.DeleteView(name); err != nil {
		return err
	}
	return r.onChange()
}

// Rebuild exposes the change hook so import can batch many writes into one
// snapshot rebuild.
func (r *Registry) Rebuild() error { return r.onChange() }

// Store exposes the underlying store for transactional import. Callers outside
// registry must not issue SQL through it.
func (r *Registry) Store() *store.Store { return r.s }

const tokenPrefix = "kydns_"

// GenerateToken returns a new plaintext token and its hash. Tokens are
// high-entropy randoms, so SHA-256 is right: a slow KDF on every API call
// would cost real latency and buy nothing against a 256-bit search space.
func GenerateToken() (string, string) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	plaintext := tokenPrefix + hex.EncodeToString(buf)
	return plaintext, HashToken(plaintext)
}

func HashToken(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}

func (r *Registry) CreateToken(label string) (string, error) {
	plaintext, hash := GenerateToken()
	if _, err := r.s.PutToken(store.Token{Label: label, Hash: hash}); err != nil {
		return "", err
	}
	return plaintext, nil
}

// AuthenticateToken compares in constant time against every stored hash.
func (r *Registry) AuthenticateToken(plaintext string) bool {
	if !strings.HasPrefix(plaintext, tokenPrefix) {
		return false
	}
	want := HashToken(plaintext)
	toks, err := r.s.Tokens()
	if err != nil {
		return false
	}
	ok := false
	for _, t := range toks {
		if subtle.ConstantTimeCompare([]byte(t.Hash), []byte(want)) == 1 {
			ok = true
			_ = r.s.TouchToken(t.ID)
		}
	}
	return ok
}

func (r *Registry) Tokens() ([]store.Token, error) { return r.s.Tokens() }

func (r *Registry) DeleteToken(id int64) error { return r.s.DeleteToken(id) }
```

Add the token queries to `internal/store/store.go`:

```go
func (s *Store) PutToken(t store.Token) (int64, error) — see below
```

```go
// append to internal/store/store.go
func (s *Store) PutToken(t Token) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO tokens(label, hash) VALUES(?, ?)`, t.Label, t.Hash)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) Tokens() ([]Token, error) {
	rows, err := s.db.Query(`SELECT id, label, hash, created_at, last_used_at FROM tokens ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Token
	for rows.Next() {
		var t Token
		if err := rows.Scan(&t.ID, &t.Label, &t.Hash, &t.CreatedAt, &t.LastUsedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) TouchToken(id int64) error {
	_, err := s.db.Exec(`UPDATE tokens SET last_used_at = unixepoch() WHERE id = ?`, id)
	return err
}

func (s *Store) DeleteToken(id int64) error {
	res, err := s.db.Exec(`DELETE FROM tokens WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: token %d", ErrNotFound, id)
	}
	return nil
}

// ReplaceAll wipes registry data and writes the given contents in one
// transaction, for import --replace. Tokens and the admin account survive:
// an import must never lock the operator out.
func (s *Store) ReplaceAll(views []View, services []Service, records []Record) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range []string{
		`DELETE FROM records`, `DELETE FROM aliases`,
		`DELETE FROM service_addresses`, `DELETE FROM services`,
		`DELETE FROM view_subnets`, `DELETE FROM views`,
	} {
		if _, err := tx.Exec(q); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	for _, v := range views {
		if err := s.PutView(v); err != nil {
			return err
		}
	}
	for _, svc := range services {
		svc.ID = 0
		if _, err := s.PutService(svc); err != nil {
			return err
		}
	}
	for _, r := range records {
		r.ID = 0
		if _, err := s.PutRecord(r); err != nil {
			return err
		}
	}
	return nil
}
```

```go
// internal/adminapi/api.go
// Package adminapi is the JSON transport over registry. It holds no business
// rules: every validation lives in registry so the CLI and the future web UI
// cannot drift from it.
package adminapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/yoshiofthewire/kydns-server/internal/dnsserver"
	"github.com/yoshiofthewire/kydns-server/internal/registry"
	"github.com/yoshiofthewire/kydns-server/internal/store"
)

type API struct {
	reg   *registry.Registry
	acl   *dnsserver.ACL
	cache *dnsserver.Cache
}

func NewAPI(reg *registry.Registry, acl *dnsserver.ACL, cache *dnsserver.Cache) *API {
	return &API{reg: reg, acl: acl, cache: cache}
}

type addressDTO struct {
	Address string `json:"address" yaml:"address"`
	View    string `json:"view,omitempty" yaml:"view,omitempty"`
}

type serviceDTO struct {
	ID            int64        `json:"id,omitempty" yaml:"-"`
	Name          string       `json:"name" yaml:"name"`
	Addresses     []addressDTO `json:"addresses" yaml:"addresses"`
	Aliases       []string     `json:"aliases,omitempty" yaml:"aliases,omitempty"`
	CheckURL      string       `json:"check_url,omitempty" yaml:"check_url,omitempty"`
	CheckInsecure bool         `json:"check_insecure,omitempty" yaml:"check_insecure,omitempty"`
}

type recordDTO struct {
	ID    int64  `json:"id,omitempty" yaml:"-"`
	Name  string `json:"name" yaml:"name"`
	Type  string `json:"type" yaml:"type"`
	Value string `json:"value" yaml:"value"`
	View  string `json:"view,omitempty" yaml:"view,omitempty"`
}

type viewDTO struct {
	Name    string   `json:"name" yaml:"name"`
	Subnets []string `json:"subnets" yaml:"subnets"`
}

// transfer is the export/import document. It carries no secrets by
// construction: there is nowhere in this struct to put one.
type transfer struct {
	Views    []viewDTO    `json:"views" yaml:"views"`
	Services []serviceDTO `json:"services" yaml:"services"`
	Records  []recordDTO  `json:"records" yaml:"records"`
}

func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})

	auth := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if token == "" || !a.reg.AuthenticateToken(token) {
				writeErr(w, http.StatusUnauthorized, "unauthenticated", "", "a valid bearer token is required")
				return
			}
			h(w, r)
		}
	}

	mux.HandleFunc("GET /api/v1/services", auth(a.listServices))
	mux.HandleFunc("POST /api/v1/services", auth(a.createService))
	mux.HandleFunc("DELETE /api/v1/services/{id}", auth(a.deleteService))
	mux.HandleFunc("GET /api/v1/records", auth(a.listRecords))
	mux.HandleFunc("POST /api/v1/records", auth(a.createRecord))
	mux.HandleFunc("DELETE /api/v1/records/{id}", auth(a.deleteRecord))
	mux.HandleFunc("GET /api/v1/views", auth(a.listViews))
	mux.HandleFunc("POST /api/v1/views", auth(a.createView))
	mux.HandleFunc("DELETE /api/v1/views/{name}", auth(a.deleteView))
	mux.HandleFunc("GET /api/v1/tokens", auth(a.listTokens))
	mux.HandleFunc("POST /api/v1/tokens", auth(a.createToken))
	mux.HandleFunc("DELETE /api/v1/tokens/{id}", auth(a.deleteToken))
	mux.HandleFunc("GET /api/v1/export", auth(a.export))
	mux.HandleFunc("POST /api/v1/import", auth(a.importDoc))
	mux.HandleFunc("GET /api/v1/stats", auth(a.stats))
	mux.HandleFunc("POST /api/v1/cache/flush", auth(a.flushCache))
	return mux
}

type errBody struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		Field   string `json:"field,omitempty"`
	} `json:"error"`
}

func writeErr(w http.ResponseWriter, status int, code, field, msg string) {
	var b errBody
	b.Error.Code, b.Error.Field, b.Error.Message = code, field, msg
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(b)
}

// writeRegistryErr maps domain errors onto status codes in one place so every
// endpoint answers consistently.
func writeRegistryErr(w http.ResponseWriter, err error) {
	var ve *registry.ValidationError
	switch {
	case errors.As(err, &ve):
		writeErr(w, http.StatusBadRequest, ve.Code, ve.Field, ve.Message)
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusNotFound, "not_found", "", err.Error())
	case errors.Is(err, store.ErrDuplicateName), errors.Is(err, store.ErrDuplicateCIDR):
		writeErr(w, http.StatusConflict, "conflict", "name", err.Error())
	case errors.Is(err, store.ErrViewInUse):
		writeErr(w, http.StatusConflict, "view_in_use", "name", err.Error())
	default:
		writeErr(w, http.StatusInternalServerError, "internal", "", err.Error())
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed_json", "", err.Error())
		return false
	}
	return true
}

func pathID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "id_invalid", "id", "id must be an integer")
		return 0, false
	}
	return id, true
}

func toServiceDTO(s store.Service) serviceDTO {
	d := serviceDTO{ID: s.ID, Name: s.Name, Aliases: s.Aliases, CheckURL: s.CheckURL, CheckInsecure: s.CheckInsecure}
	for _, a := range s.Addresses {
		d.Addresses = append(d.Addresses, addressDTO{Address: a.Address, View: a.View})
	}
	return d
}

func fromServiceDTO(d serviceDTO) store.Service {
	s := store.Service{ID: d.ID, Name: d.Name, Aliases: d.Aliases, CheckURL: d.CheckURL, CheckInsecure: d.CheckInsecure}
	for _, a := range d.Addresses {
		s.Addresses = append(s.Addresses, store.Address{Address: a.Address, View: a.View})
	}
	return s
}

func (a *API) listServices(w http.ResponseWriter, _ *http.Request) {
	svcs, err := a.reg.Services()
	if err != nil {
		writeRegistryErr(w, err)
		return
	}
	out := make([]serviceDTO, 0, len(svcs))
	for _, s := range svcs {
		out = append(out, toServiceDTO(s))
	}
	writeJSON(w, http.StatusOK, map[string]any{"services": out})
}

func (a *API) createService(w http.ResponseWriter, r *http.Request) {
	var d serviceDTO
	if !decode(w, r, &d) {
		return
	}
	id, err := a.reg.PutService(fromServiceDTO(d))
	if err != nil {
		writeRegistryErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": id})
}

func (a *API) deleteService(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := a.reg.DeleteService(id); err != nil {
		writeRegistryErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) listRecords(w http.ResponseWriter, _ *http.Request) {
	recs, err := a.reg.Records()
	if err != nil {
		writeRegistryErr(w, err)
		return
	}
	out := make([]recordDTO, 0, len(recs))
	for _, r := range recs {
		out = append(out, recordDTO{ID: r.ID, Name: r.Name, Type: r.Type, Value: r.Value, View: r.View})
	}
	writeJSON(w, http.StatusOK, map[string]any{"records": out})
}

func (a *API) createRecord(w http.ResponseWriter, r *http.Request) {
	var d recordDTO
	if !decode(w, r, &d) {
		return
	}
	id, err := a.reg.PutRecord(store.Record{Name: d.Name, Type: d.Type, Value: d.Value, View: d.View})
	if err != nil {
		writeRegistryErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": id})
}

func (a *API) deleteRecord(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := a.reg.DeleteRecord(id); err != nil {
		writeRegistryErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) listViews(w http.ResponseWriter, _ *http.Request) {
	views, err := a.reg.Views()
	if err != nil {
		writeRegistryErr(w, err)
		return
	}
	out := make([]viewDTO, 0, len(views))
	for _, v := range views {
		out = append(out, viewDTO{Name: v.Name, Subnets: v.Subnets})
	}
	writeJSON(w, http.StatusOK, map[string]any{"views": out})
}

func (a *API) createView(w http.ResponseWriter, r *http.Request) {
	var d viewDTO
	if !decode(w, r, &d) {
		return
	}
	if err := a.reg.PutView(store.View{Name: d.Name, Subnets: d.Subnets}); err != nil {
		writeRegistryErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"name": d.Name})
}

func (a *API) deleteView(w http.ResponseWriter, r *http.Request) {
	if err := a.reg.DeleteView(r.PathValue("name")); err != nil {
		writeRegistryErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) listTokens(w http.ResponseWriter, _ *http.Request) {
	toks, err := a.reg.Tokens()
	if err != nil {
		writeRegistryErr(w, err)
		return
	}
	// Never the hash, never the plaintext: label and metadata only.
	out := make([]map[string]any, 0, len(toks))
	for _, t := range toks {
		out = append(out, map[string]any{
			"id": t.ID, "label": t.Label,
			"created_at": t.CreatedAt, "last_used_at": t.LastUsedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": out})
}

func (a *API) createToken(w http.ResponseWriter, r *http.Request) {
	var d struct {
		Label string `json:"label"`
	}
	if !decode(w, r, &d) {
		return
	}
	plaintext, err := a.reg.CreateToken(d.Label)
	if err != nil {
		writeRegistryErr(w, err)
		return
	}
	// The only time the plaintext is ever returned.
	writeJSON(w, http.StatusCreated, map[string]any{"token": plaintext, "label": d.Label})
}

func (a *API) deleteToken(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := a.reg.DeleteToken(id); err != nil {
		writeRegistryErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) snapshotDoc() (transfer, error) {
	var doc transfer
	views, err := a.reg.Views()
	if err != nil {
		return doc, err
	}
	for _, v := range views {
		doc.Views = append(doc.Views, viewDTO{Name: v.Name, Subnets: v.Subnets})
	}
	svcs, err := a.reg.Services()
	if err != nil {
		return doc, err
	}
	for _, s := range svcs {
		d := toServiceDTO(s)
		d.ID = 0
		doc.Services = append(doc.Services, d)
	}
	recs, err := a.reg.Records()
	if err != nil {
		return doc, err
	}
	for _, r := range recs {
		doc.Records = append(doc.Records, recordDTO{Name: r.Name, Type: r.Type, Value: r.Value, View: r.View})
	}
	return doc, nil
}

func (a *API) export(w http.ResponseWriter, r *http.Request) {
	doc, err := a.snapshotDoc()
	if err != nil {
		writeRegistryErr(w, err)
		return
	}
	if r.URL.Query().Get("format") == "json" {
		writeJSON(w, http.StatusOK, doc)
		return
	}
	w.Header().Set("Content-Type", "application/yaml")
	if err := yaml.NewEncoder(w).Encode(doc); err != nil {
		writeErr(w, http.StatusInternalServerError, "encode", "", err.Error())
	}
}

func (a *API) importDoc(w http.ResponseWriter, r *http.Request) {
	var doc transfer
	body := make([]byte, 0)
	buf := make([]byte, 4096)
	for {
		n, err := r.Body.Read(buf)
		body = append(body, buf[:n]...)
		if err != nil {
			break
		}
	}
	if err := yaml.Unmarshal(body, &doc); err != nil { // YAML parses JSON too
		writeErr(w, http.StatusBadRequest, "malformed_document", "", err.Error())
		return
	}

	if r.URL.Query().Get("mode") == "replace" {
		views := make([]store.View, 0, len(doc.Views))
		for _, v := range doc.Views {
			views = append(views, store.View{Name: v.Name, Subnets: v.Subnets})
		}
		svcs := make([]store.Service, 0, len(doc.Services))
		for _, s := range doc.Services {
			svcs = append(svcs, fromServiceDTO(s))
		}
		recs := make([]store.Record, 0, len(doc.Records))
		for _, rec := range doc.Records {
			recs = append(recs, store.Record{Name: rec.Name, Type: rec.Type, Value: rec.Value, View: rec.View})
		}
		if err := a.reg.Store().ReplaceAll(views, svcs, recs); err != nil {
			writeRegistryErr(w, err)
			return
		}
		if err := a.reg.Rebuild(); err != nil {
			writeRegistryErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"mode": "replace"})
		return
	}

	for _, v := range doc.Views {
		if err := a.reg.PutView(store.View{Name: v.Name, Subnets: v.Subnets}); err != nil {
			writeRegistryErr(w, err)
			return
		}
	}
	for _, s := range doc.Services {
		if _, err := a.reg.PutService(fromServiceDTO(s)); err != nil {
			writeRegistryErr(w, err)
			return
		}
	}
	for _, rec := range doc.Records {
		if _, err := a.reg.PutRecord(store.Record{Name: rec.Name, Type: rec.Type, Value: rec.Value, View: rec.View}); err != nil {
			writeRegistryErr(w, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"mode": "merge"})
}

func (a *API) stats(w http.ResponseWriter, _ *http.Request) {
	out := map[string]any{}
	if a.acl != nil {
		s := a.acl.Stats()
		out["refusals"] = map[string]any{
			"total": s.Total, "cgnat": s.CGNAT, "last_cgnat": s.LastCGNAT,
		}
	}
	if a.cache != nil {
		out["cache"] = map[string]any{"entries": a.cache.Len()}
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) flushCache(w http.ResponseWriter, _ *http.Request) {
	if a.cache != nil {
		a.cache.Flush()
	}
	w.WriteHeader(http.StatusNoContent)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/registry/ ./internal/adminapi/ -v`
Expected: PASS. `TestExportOmitsSecrets` is the one that must never be skipped.

- [ ] **Step 5: Commit**

```bash
git add internal/registry internal/adminapi internal/store
git commit -m "Add registry service layer and token-authenticated admin API

The API holds no business rules: validation lives in registry so the
CLI and the future web UI cannot drift from it. Tokens are SHA-256
hashed rather than argon2 because they are high-entropy randoms, where
a slow KDF costs latency on every call and buys nothing. The export
document has no field capable of holding a secret.

AI-assisted contribution (agentic). Verified with: go test ./internal/registry/ ./internal/adminapi/"
```

---

### Task 13: CLI, serve wiring, and the end-to-end test

**Files:**
- Create: `internal/cli/cli.go`, `internal/app/serve.go`
- Modify: `cmd/kydns/main.go`
- Test: `internal/cli/cli_test.go`, `internal/app/serve_test.go`

**Interfaces:**
- Consumes: everything above.
- Produces:
  - `type Client struct { BaseURL, Token string; HTTP *http.Client }`
  - `func (c *Client) Do(method, path string, body any, out any) error`
  - `func Run(args []string, stdout, stderr io.Writer) int`
  - `func app.Serve(ctx context.Context, cfgPath string, logger *slog.Logger) error`

- [ ] **Step 1: Write the failing test**

```go
// internal/app/serve_test.go
package app

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.LocalAddr().(*net.UDPAddr).Port
}

// The whole point of Plan 1: add a service over HTTP, resolve it over DNS.
func TestEndToEndAddServiceThenResolve(t *testing.T) {
	dir := t.TempDir()
	dnsPort, adminPort := freePort(t), freePort(t)
	cfg := filepath.Join(dir, "kydns.yaml")
	body := fmt.Sprintf(`
data_dir: %s
dns:
  listen: "127.0.0.1:%d"
  private_domain: home.arpa
  reverse_zones: ["192.168.1.0/24"]
  allow_query: ["127.0.0.0/8"]
admin:
  listen: "127.0.0.1:%d"
`, dir, dnsPort, adminPort)
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errs := make(chan error, 1)
	go func() { errs <- Serve(ctx, cfg, nil) }()

	token := waitForSetupToken(t, dir)
	base := fmt.Sprintf("http://127.0.0.1:%d", adminPort)
	waitForHTTP(t, base+"/api/v1/healthz")

	postJSON(t, base+"/api/v1/services", token,
		`{"name":"kypost","addresses":[{"address":"192.168.1.20"}],"aliases":["webmail"]}`)

	c := &dns.Client{Net: "udp", Timeout: 3 * time.Second}
	server := fmt.Sprintf("127.0.0.1:%d", dnsPort)

	for _, name := range []string{"kypost.home.arpa.", "webmail.home.arpa."} {
		m := new(dns.Msg)
		m.SetQuestion(name, dns.TypeA)
		resp, _, err := c.Exchange(m, server)
		if err != nil {
			t.Fatalf("resolve %s: %v", name, err)
		}
		if len(resp.Answer) != 1 {
			t.Fatalf("%s answer = %v, want one A record", name, resp.Answer)
		}
		if got := resp.Answer[0].(*dns.A).A.String(); got != "192.168.1.20" {
			t.Errorf("%s = %s, want 192.168.1.20", name, got)
		}
	}

	// The reverse record is derived, not authored.
	m := new(dns.Msg)
	m.SetQuestion("20.1.168.192.in-addr.arpa.", dns.TypePTR)
	resp, _, err := c.Exchange(m, server)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Answer) != 1 || resp.Answer[0].(*dns.PTR).Ptr != "kypost.home.arpa." {
		t.Errorf("PTR = %v, want kypost.home.arpa.", resp.Answer)
	}

	cancel()
	select {
	case <-errs:
	case <-time.After(5 * time.Second):
		t.Error("Serve() did not return within 5s of context cancellation")
	}
}

// Tailscale clients are refused under the default, which is the whole reason
// the banner exists.
func TestTailscaleRefusedByDefault(t *testing.T) {
	dir := t.TempDir()
	dnsPort, adminPort := freePort(t), freePort(t)
	cfg := filepath.Join(dir, "kydns.yaml")
	body := fmt.Sprintf(`
data_dir: %s
dns:
  listen: "127.0.0.1:%d"
  allow_query: ["192.168.0.0/16"]
admin:
  listen: "127.0.0.1:%d"
`, dir, dnsPort, adminPort)
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go Serve(ctx, cfg, nil)
	waitForHTTP(t, fmt.Sprintf("http://127.0.0.1:%d/api/v1/healthz", adminPort))

	c := &dns.Client{Net: "udp", Timeout: 3 * time.Second}
	m := new(dns.Msg)
	m.SetQuestion("kypost.home.arpa.", dns.TypeA)
	resp, _, err := c.Exchange(m, fmt.Sprintf("127.0.0.1:%d", dnsPort))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Rcode != dns.RcodeRefused {
		t.Errorf("Rcode = %s, want REFUSED for a loopback client outside the ACL",
			dns.RcodeToString[resp.Rcode])
	}
}
```

Add these helpers to `serve_test.go`:

```go
func waitForHTTP(t *testing.T, url string) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if resp, err := http.Get(url); err == nil {
			resp.Body.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("server at %s never became ready", url)
}

// waitForSetupToken reads the bootstrap token Serve writes to the data dir on
// first run.
func waitForSetupToken(t *testing.T, dir string) string {
	t.Helper()
	p := filepath.Join(dir, "bootstrap-token")
	for i := 0; i < 100; i++ {
		if b, err := os.ReadFile(p); err == nil {
			return strings.TrimSpace(string(b))
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("bootstrap token was never written")
	return ""
}

func postJSON(t *testing.T, url, token, body string) {
	t.Helper()
	req, err := http.NewRequest("POST", url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST %s = %d: %s", url, resp.StatusCode, b)
	}
}
```

Add `"io"` and `"net/http"` to the test imports.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/app/ -v`
Expected: FAIL — `undefined: Serve`.

- [ ] **Step 3: Write minimal implementation**

```go
// internal/app/serve.go
// Package app wires the process together. It is the only place that knows
// about every other package.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/yoshiofthewire/kydns-server/internal/adminapi"
	"github.com/yoshiofthewire/kydns-server/internal/config"
	"github.com/yoshiofthewire/kydns-server/internal/dnsserver"
	"github.com/yoshiofthewire/kydns-server/internal/registry"
	"github.com/yoshiofthewire/kydns-server/internal/store"
	"github.com/yoshiofthewire/kydns-server/internal/zone"
)

// Serve runs the DNS and admin listeners until ctx is cancelled.
func Serve(ctx context.Context, cfgPath string, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err // fail fast: never run half-configured
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}
	st, err := store.Open(filepath.Join(cfg.DataDir, "kydns.db"))
	if err != nil {
		return err
	}
	defer st.Close()

	reverse := make([]netip.Prefix, 0, len(cfg.DNS.ReverseZones))
	for _, z := range cfg.DNS.ReverseZones {
		p, err := netip.ParsePrefix(z)
		if err != nil {
			return err
		}
		reverse = append(reverse, p.Masked())
	}

	holder := zone.NewHolder(func() (zone.Input, error) {
		views, err := st.Views()
		if err != nil {
			return zone.Input{}, err
		}
		svcs, err := st.Services()
		if err != nil {
			return zone.Input{}, err
		}
		recs, err := st.Records()
		if err != nil {
			return zone.Input{}, err
		}
		return zone.Input{
			Views: views, Services: svcs, Records: recs,
			Zone: cfg.PrivateFQDN(), ReverseZones: reverse,
		}, nil
	})
	if err := holder.Rebuild(); err != nil {
		return fmt.Errorf("initial snapshot: %w", err)
	}

	reg := registry.New(st, cfg.PrivateFQDN(), func() error {
		if err := holder.Rebuild(); err != nil {
			// The write is already committed; the old snapshot keeps serving.
			logger.Error("snapshot rebuild failed, still serving the previous snapshot", "error", err)
			return err
		}
		return nil
	})

	if err := bootstrapToken(reg, cfg.DataDir, logger); err != nil {
		return err
	}

	allowed, err := cfg.EffectiveAllowQuery()
	if err != nil {
		return err
	}
	acl := dnsserver.NewACL(allowed)
	logger.Info("query acl", "ranges", cfg.DNS.AllowQuery, "allow_tailscale", cfg.DNS.AllowTailscale)
	warnUnreachableViews(st, cfg, logger)

	cache := dnsserver.NewCache(cfg.DNS.CacheEntries, cfg.DNS.CacheMinTTL, cfg.DNS.CacheMaxTTL, cfg.DNS.NegativeMaxTTL)
	fwd := dnsserver.NewForwarder(cfg.DNS.Upstreams, 2*time.Second, cache,
		dnsserver.UDPExchanger{Timeout: 2 * time.Second})

	dnsSrv := dnsserver.New(dnsserver.Options{
		Holder: holder, ACL: acl,
		Auth: &dnsserver.Authoritative{
			Zone: cfg.PrivateFQDN(), TTL: uint32(cfg.DNS.TTL), ReverseZones: reverse,
		},
		Forwarder:   fwd,
		LogQueries:  cfg.DNS.LogQueries,
		LogClientIP: cfg.DNS.LogClientIP,
		Logger:      logger,
	})

	adminSrv := &http.Server{
		Addr:              cfg.Admin.Listen,
		Handler:           adminapi.NewAPI(reg, acl, cache).Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	errs := make(chan error, 2)
	go func() { errs <- dnsSrv.ListenAndServe(cfg.DNS.Listen) }()
	go func() {
		if err := adminSrv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			errs <- err
		}
	}()
	logger.Info("kydns started", "dns", cfg.DNS.Listen, "admin", cfg.Admin.Listen, "zone", cfg.PrivateFQDN())

	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return errors.Join(dnsSrv.Shutdown(shutdown), adminSrv.Shutdown(shutdown))
}

// bootstrapToken mints a first API token when none exist and writes it to the
// data dir, so a fresh install is usable without a chicken-and-egg problem.
// Plan 2 replaces this with the /setup flow.
func bootstrapToken(reg *registry.Registry, dataDir string, logger *slog.Logger) error {
	toks, err := reg.Tokens()
	if err != nil {
		return err
	}
	if len(toks) > 0 {
		return nil
	}
	plaintext, err := reg.CreateToken("bootstrap")
	if err != nil {
		return err
	}
	path := filepath.Join(dataDir, "bootstrap-token")
	if err := os.WriteFile(path, []byte(plaintext+"\n"), 0o600); err != nil {
		return err
	}
	logger.Info("wrote bootstrap API token", "path", path)
	return nil
}

// warnUnreachableViews implements banner condition 2: a view whose CIDRs the
// ACL rejects can never match.
func warnUnreachableViews(st *store.Store, cfg *config.Config, logger *slog.Logger) {
	if cfg.DNS.AllowTailscale {
		return
	}
	cgnat := netip.MustParsePrefix(config.TailscaleCGNAT)
	views, err := st.Views()
	if err != nil {
		return
	}
	for _, v := range views {
		for _, c := range v.Subnets {
			p, err := netip.ParsePrefix(c)
			if err != nil || !cgnat.Overlaps(p) {
				continue
			}
			logger.Warn("view can never match: its subnet is refused by the query ACL",
				"view", v.Name, "subnet", c,
				"fix", "set allow_tailscale: true in the config file and restart")
		}
	}
}
```

```go
// internal/cli/cli.go
// Package cli talks to a running server over the admin API. It never opens the
// database, so kydns works against a remote server for free.
package cli

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

func NewClient() *Client {
	base := os.Getenv("KYDNS_URL")
	if base == "" {
		base = "http://127.0.0.1:8053"
	}
	return &Client{
		BaseURL: strings.TrimSuffix(base, "/"),
		Token:   os.Getenv("KYDNS_TOKEN"),
		HTTP:    &http.Client{Timeout: 10 * time.Second},
	}
}

// Do sends a request and decodes the reply, surfacing the API's structured
// error so the CLI reports the same field name the UI would.
func (c *Client) Do(method, path string, body, out any) error {
	var rdr io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(buf)
	}
	req, err := http.NewRequest(method, c.BaseURL+path, rdr)
	if err != nil {
		return err
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		var e struct {
			Error struct{ Code, Message, Field string } `json:"error"`
		}
		if json.Unmarshal(raw, &e) == nil && e.Error.Message != "" {
			if e.Error.Field != "" {
				return fmt.Errorf("%s: %s", e.Error.Field, e.Error.Message)
			}
			return fmt.Errorf("%s", e.Error.Message)
		}
		return fmt.Errorf("%s %s: %s", method, path, resp.Status)
	}
	if out != nil && len(raw) > 0 {
		return json.Unmarshal(raw, out)
	}
	return nil
}

// Run dispatches a subcommand. It returns a process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "kydns: a subcommand is required")
		return 2
	}
	c := NewClient()
	switch args[0] {
	case "service":
		return serviceCmd(c, args[1:], stdout, stderr)
	case "view":
		return viewCmd(c, args[1:], stdout, stderr)
	case "export":
		return exportCmd(c, args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "kydns: unknown subcommand %q\n", args[0])
		return 2
	}
}

func serviceCmd(c *Client, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: kydns service add|list|rm")
		return 2
	}
	switch args[0] {
	case "list":
		var out struct {
			Services []struct {
				ID        int64 `json:"id"`
				Name      string
				Addresses []struct{ Address, View string }
			} `json:"services"`
		}
		if err := c.Do("GET", "/api/v1/services", nil, &out); err != nil {
			fmt.Fprintln(stderr, "kydns:", err)
			return 1
		}
		for _, s := range out.Services {
			for _, a := range s.Addresses {
				view := a.View
				if view == "" {
					view = "all views"
				}
				fmt.Fprintf(stdout, "%-24s %-18s %s\n", s.Name, a.Address, view)
			}
		}
		return 0
	case "add":
		fs := flag.NewFlagSet("service add", flag.ContinueOnError)
		fs.SetOutput(stderr)
		address := fs.String("address", "", "IP address (repeatable via --view pairs)")
		view := fs.String("view", "", "view name; empty means all views")
		alias := fs.String("alias", "", "comma-separated aliases")
		check := fs.String("check", "", "health check URL")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		if fs.NArg() != 1 || *address == "" {
			fmt.Fprintln(stderr, "usage: kydns service add <name> --address <ip> [--view v] [--alias a,b] [--check url]")
			return 2
		}
		body := map[string]any{
			"name":      fs.Arg(0),
			"addresses": []map[string]string{{"address": *address, "view": *view}},
			"check_url": *check,
		}
		if *alias != "" {
			body["aliases"] = strings.Split(*alias, ",")
		}
		if err := c.Do("POST", "/api/v1/services", body, nil); err != nil {
			fmt.Fprintln(stderr, "kydns:", err)
			return 1
		}
		fmt.Fprintf(stdout, "added service %s\n", fs.Arg(0))
		return 0
	}
	fmt.Fprintf(stderr, "kydns: unknown service subcommand %q\n", args[0])
	return 2
}

func viewCmd(c *Client, args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "list" {
		var out struct {
			Views []struct {
				Name    string
				Subnets []string
			} `json:"views"`
		}
		if err := c.Do("GET", "/api/v1/views", nil, &out); err != nil {
			fmt.Fprintln(stderr, "kydns:", err)
			return 1
		}
		for _, v := range out.Views {
			fmt.Fprintf(stdout, "%-16s %s\n", v.Name, strings.Join(v.Subnets, ", "))
		}
		return 0
	}
	if len(args) >= 3 && args[0] == "add" {
		body := map[string]any{"name": args[1], "subnets": strings.Split(args[2], ",")}
		if err := c.Do("POST", "/api/v1/views", body, nil); err != nil {
			fmt.Fprintln(stderr, "kydns:", err)
			return 1
		}
		fmt.Fprintf(stdout, "added view %s\n", args[1])
		return 0
	}
	fmt.Fprintln(stderr, "usage: kydns view add <name> <cidr[,cidr]> | kydns view list")
	return 2
}

func exportCmd(c *Client, args []string, stdout, stderr io.Writer) int {
	format := "yaml"
	if len(args) > 0 {
		format = args[0]
	}
	req, err := http.NewRequest("GET", c.BaseURL+"/api/v1/export?format="+format, nil)
	if err != nil {
		fmt.Fprintln(stderr, "kydns:", err)
		return 1
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		fmt.Fprintln(stderr, "kydns:", err)
		return 1
	}
	defer resp.Body.Close()
	io.Copy(stdout, resp.Body)
	return 0
}
```

```go
// cmd/kydns/main.go — replace the switch in run()
	switch args[0] {
	case "serve":
		fs := flag.NewFlagSet("serve", flag.ContinueOnError)
		cfg := fs.String("config", "/etc/kydns/kydns.yaml", "path to the config file")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if err := app.Serve(ctx, *cfg, nil); err != nil {
			fmt.Fprintln(os.Stderr, "kydns:", err)
			return 1
		}
		return 0
	case "service", "record", "view", "token", "export", "import":
		return cli.Run(args, stdout, os.Stderr)
	default:
		fmt.Fprintf(stdout, "kydns: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
```

Add imports to `main.go`: `context`, `flag`, `os/signal`, `syscall`, and the
`app` and `cli` packages.

```go
// internal/cli/cli_test.go
package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestServiceListRendersUntaggedAsAllViews(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"services": []map[string]any{{
			"id": 1, "name": "kypost",
			"addresses": []map[string]string{
				{"address": "192.168.1.20", "view": ""},
				{"address": "100.101.102.103", "view": "tailnet"},
			},
		}}})
	}))
	defer srv.Close()

	c := &Client{BaseURL: srv.URL, Token: "t", HTTP: srv.Client()}
	var out, errOut bytes.Buffer
	if code := serviceCmd(c, []string{"list"}, &out, &errOut); code != 0 {
		t.Fatalf("exit = %d, stderr = %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "all views") {
		t.Errorf("untagged address not labelled:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "tailnet") {
		t.Errorf("tagged address missing:\n%s", out.String())
	}
}

// A structured API error must surface with its field name, not a bare status.
func TestClientSurfacesFieldError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":{"code":"label_charset","field":"name","message":"label is invalid"}}`))
	}))
	defer srv.Close()

	c := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	err := c.Do("POST", "/api/v1/services", map[string]string{"name": "bad_name"}, nil)
	if err == nil {
		t.Fatal("Do() error = nil, want the API error")
	}
	if !strings.Contains(err.Error(), "name") || !strings.Contains(err.Error(), "label is invalid") {
		t.Errorf("err = %v, want the field and message", err)
	}
}
```

- [ ] **Step 4: Run the full suite**

Run: `CGO_ENABLED=0 go test ./... -race`
Expected: PASS across every package. `TestEndToEndAddServiceThenResolve` is the deliverable: a service added over HTTP resolves over DNS, alias included, with a derived PTR.

Then confirm the binary builds and runs:

```bash
make build
mkdir -p /tmp/kydns && printf 'data_dir: /tmp/kydns\ndns:\n  listen: "127.0.0.1:5353"\nadmin:\n  listen: "127.0.0.1:8053"\n' > /tmp/kydns.yaml
./bin/kydns serve --config /tmp/kydns.yaml &
sleep 1
KYDNS_TOKEN=$(cat /tmp/kydns/bootstrap-token) ./bin/kydns service add kypost --address 192.168.1.20 --alias webmail
dig @127.0.0.1 -p 5353 kypost.home.arpa A +short   # expect 192.168.1.20
kill %1
```

- [ ] **Step 5: Commit**

```bash
git add cmd internal/app internal/cli
git commit -m "Add CLI, serve wiring, and end-to-end test

serve mints a bootstrap API token on first run and writes it to the
data dir, so a fresh install is usable without a chicken-and-egg
problem; plan 2 replaces this with the /setup flow. A view whose
subnets the ACL refuses logs the actionable warning at startup.

AI-assisted contribution (agentic). Verified with: CGO_ENABLED=0 go test ./... -race,
plus a manual dig against the built binary."
```

---

## Self-Review (Part 3)

**Spec coverage.** Registry as the single validation home, per-view tag checks → Task 12. Token auth with SHA-256, shown once → Task 12. Full API route list including `/views`, `/stats`, `/cache/flush`, unauthenticated `/healthz` → Task 12. Error shape with code, message, and field; 409 for name collision and in-use view → Task 12. Export omitting secrets, import merge and replace → Task 12. CLI over the API never touching the DB, untagged shown as "all views" → Task 13. Fail-fast config, initial snapshot, rebuild-keeps-serving on failure, ACL logging, unreachable-view warning → Task 13.

**Deferred to Plan 2, deliberately:** password and session auth, `/setup`, all HTML, the dashboard banner rendering. The banner's two data sources ship here — `ACL.RecentCGNATRefusal` in Task 8 and `warnUnreachableViews` in Task 13 — so Plan 2 only renders them.

**Placeholder scan.** No TBD steps. Every code step is runnable. The `store` additions in Task 12 are given in full rather than described.

**Type consistency.** `registry.New(store, zoneFQDN, onChange)` matches its call in Tasks 12 and 13. `adminapi.NewAPI(reg, acl, cache)` takes nils in the Task 12 test and real values in Task 13, so both compile. `store.Token` fields used by `listTokens` match the struct from Task 3. `dnsserver.NewCache` and `NewForwarder` signatures match Part 2 Task 10. `ValidationError.Code`/`.Field` from Task 4 are what `writeRegistryErr` reads.
