### Task 11: API and CLI surface

**Files:**
- Modify: `internal/adminapi/settings.go`, `internal/adminapi/api.go` (route table), `internal/cli/settings.go`
- Test: `internal/adminapi/settings_test.go`, `internal/adminapi/dhcp_test.go`, `internal/cli/settings_test.go`

**Interfaces:**
- Produces: the seven `dhcp_*` fields in the settings JSON; `GET /api/dhcp/leases` returning `{"running":bool,"error":string,"leases":[{"mac","ip","hostname","expires"}]}`.

- [ ] **Step 1: Write the failing tests**

Create `internal/adminapi/dhcp_test.go`:

```go
package adminapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSettingsJSONCarriesDHCPFields(t *testing.T) {
	h, tok := newTestAPI(t) // the existing helper in this package
	req := httptest.NewRequest(http.MethodGet, "/api/settings", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, k := range []string{
		"dhcp_enabled", "dhcp_interface", "dhcp_range_start", "dhcp_range_end",
		"dhcp_gateway", "dhcp_lease_seconds", "dhcp_secondary_dns",
	} {
		if _, ok := body[k]; !ok {
			t.Fatalf("settings JSON has no %q; the CLI and UI read this", k)
		}
	}
}

func TestDHCPLeasesEndpointReportsNotRunning(t *testing.T) {
	h, tok := newTestAPI(t)
	req := httptest.NewRequest(http.MethodGet, "/api/dhcp/leases", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 even when DHCP is off", rec.Code)
	}
	var body struct {
		Running bool `json:"running"`
		Leases  []struct{ MAC string } `json:"leases"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Running {
		t.Fatal("running = true with DHCP disabled")
	}
	if len(body.Leases) != 0 {
		t.Fatalf("leases = %+v, want none", body.Leases)
	}
}

func TestDHCPLeasesRequiresAuth(t *testing.T) {
	h, _ := newTestAPI(t)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/dhcp/leases", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401: lease data names devices on the network", rec.Code)
	}
}

func TestDHCPSettingsRejectedOnAReplica(t *testing.T) {
	// A replica refuses administrative writes with the address of the node to
	// make them on. DHCP settings are no exception.
	h, tok := newTestReplicaAPI(t) // the existing helper used by writegate_test.go
	req := httptest.NewRequest(http.MethodPut, "/api/settings", strings.NewReader(`{"dhcp_enabled":true}`))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatal("a replica accepted a settings write")
	}
}
```

Use the helper names this package already has — check `internal/adminapi/settings_test.go` and `writegate_test.go` for what `newTestAPI` and the replica equivalent are actually called, and do not add new ones.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/adminapi/ -run DHCP -v`
Expected: FAIL — the settings JSON has no `dhcp_enabled`, and `/api/dhcp/leases` 404s.

- [ ] **Step 3: Add the settings fields**

In `internal/adminapi/settings.go`, add to the settings DTO, matching the existing `json` tag style:

```go
	DHCPEnabled      bool   `json:"dhcp_enabled"`
	DHCPInterface    string `json:"dhcp_interface"`
	DHCPRangeStart   string `json:"dhcp_range_start"`
	DHCPRangeEnd     string `json:"dhcp_range_end"`
	DHCPGateway      string `json:"dhcp_gateway"`
	DHCPLeaseSeconds int    `json:"dhcp_lease_seconds"`
	DHCPSecondaryDNS string `json:"dhcp_secondary_dns"`
```

Wire them through both directions of the existing DTO-to-`store.Settings` conversion. Follow whatever pattern the neighbouring fields use; do not introduce a second one.

- [ ] **Step 4: Add the lease endpoint**

Create `internal/adminapi/dhcp.go`:

```go
package adminapi

import (
	"net/http"
	"time"
)

// DHCPStatus is what the leases endpoint returns. It reports running and any
// error separately from the lease list, because "no leases" and "not running"
// are different things an operator needs told apart.
type DHCPStatus struct {
	Running bool        `json:"running"`
	Error   string      `json:"error,omitempty"`
	Leases  []DHCPLease `json:"leases"`
}

type DHCPLease struct {
	MAC      string `json:"mac"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
	Expires  string `json:"expires"`
}

func (a *API) dhcpLeases(w http.ResponseWriter, r *http.Request) {
	out := DHCPStatus{Leases: []DHCPLease{}}
	if a.DHCP != nil {
		running, err := a.DHCP.Status()
		out.Running = running
		if err != nil {
			out.Error = err.Error()
		}
	}
	if a.Leases != nil {
		for _, l := range a.Leases() {
			out.Leases = append(out.Leases, DHCPLease{
				MAC:      l.MAC,
				IP:       l.IP,
				Hostname: l.Hostname,
				Expires:  l.Expires.Format(time.RFC3339),
			})
		}
	}
	writeJSON(w, http.StatusOK, out)
}
```

`a.Leases` is the existing `func() []dhcp.Lease` field wired at `internal/app/serve.go:313`. Add a `DHCP` field to the `API` struct with an interface type declared next to it:

```go
	// DHCPStatuser is the runner slice the API needs. It is nil when the
	// build has no DHCP runner, which is every test that does not want one.
	DHCP interface{ Status() (bool, error) }
```

Register the route beside the other read-only endpoints in `internal/adminapi/api.go`, behind the same auth middleware:

```go
	mux.HandleFunc("GET /api/dhcp/leases", a.dhcpLeases)
```

Use whatever registration form the neighbouring routes use.

- [ ] **Step 5: Pass the runner in**

In `internal/app/serve.go`, where the `adminapi.API` is constructed, add `DHCP: dhcpRun`.

- [ ] **Step 6: Add the CLI**

In `internal/cli/settings.go`, add the seven keys to the settings get/set table so `kydns settings set dhcp.enabled true` works. Follow the existing key-name convention exactly — if other keys are dotted (`health.interval`), these are `dhcp.enabled`, `dhcp.interface`, `dhcp.range_start`, `dhcp.range_end`, `dhcp.gateway`, `dhcp.lease_seconds`, `dhcp.secondary_dns`.

Add a `kydns dhcp leases` command that GETs `/api/dhcp/leases` and prints a table, matching how the CLI renders other lists. When `running` is false and `error` is non-empty, print the error instead of an empty table — an operator who enabled DHCP and sees nothing needs the reason, not a blank.

- [ ] **Step 7: Write the CLI test**

Add to `internal/cli/settings_test.go`, following the pattern the existing tests in that file use for a fake API server:

```go
func TestSettingsSetDHCPEnabled(t *testing.T) {
	var got map[string]any
	srv := fakeAPI(t, func(body map[string]any) { got = body })
	defer srv.Close()

	if err := run(t, srv.URL, "settings", "set", "dhcp.enabled", "true"); err != nil {
		t.Fatalf("run: %v", err)
	}
	if got["dhcp_enabled"] != true {
		t.Fatalf("PUT body dhcp_enabled = %v, want true", got["dhcp_enabled"])
	}
}
```

`fakeAPI` and `run` are placeholders for whatever this file already uses. Read the neighbouring test before writing this one and match it.

- [ ] **Step 8: Run the tests**

Run: `go test ./internal/adminapi/... ./internal/cli/... -v`
Expected: PASS.

- [ ] **Step 9: Run the whole suite**

Run: `go test ./... -count=1 && go vet ./...`
Expected: PASS, no vet output.

- [ ] **Step 10: Commit**

```bash
git add internal/adminapi/ internal/cli/ internal/app/serve.go
git commit -m "feat(api,cli): expose DHCP settings and the lease table

Running and error are reported separately from the lease list: 'no
leases' and 'not running' are different things, and an operator who
turned DHCP on and sees nothing needs the reason rather than a blank."
```

---

## Self-Review

**Spec coverage.** Every section of the spec that Part 1 owns maps to a task: sockets and the broadcast decision (Task 7), settings and the live-apply change (Tasks 2, 9, 10), lease allocation and the store (Tasks 3, 5), conflict probing (Task 6), rogue detection (Tasks 8, 10), replication's primary-only rule (Task 10, `dhcpWanted`), the operator surface for API and CLI (Task 11), and packaging (Task 10, Step 7).

Deferred to Part 2, by design: reservations as a MAC on `Service` (the spec's "Reservations" section), the setup wizard, the web DHCP tab, the dual-stack note, the periodic 15-minute rogue probe and its banner, and the documentation updates. Task 5 ships `SetReservations` unused so Part 2 has the seam it needs without reopening the allocator.

**Known gap carried into Part 2.** Task 10's `build` treats a foreign server as a hard refusal with no override. The spec requires an override that is off by default; it needs a settings field and a UI affordance, so it lands with the DHCP tab in Part 2. Until then the behaviour is stricter than the spec, not looser — an operator who genuinely runs two servers cannot enable DHCP yet. That is the safe direction to be wrong in, and Part 2 Task 1 closes it.

**Type consistency.** `Lease` is `dhcpd.Lease` (netip, time.Time) inside the package, `store.DHCPLease` (strings, Unix seconds) at the storage boundary, and `discovery/dhcp.Lease` at the DNS boundary; `Server.Leases` is the only conversion between the last two, and `Server.restore` the only one between the first two. MAC normalization is `normalizeMAC` in one place, and Part 2's reservations must call it.
