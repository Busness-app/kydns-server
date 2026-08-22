package adminapi

import (
	"encoding/json"
	"maps"
	"net/http"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/yoshiofthewire/kydns-server/internal/registry"
	"github.com/yoshiofthewire/kydns-server/internal/settings"
	"github.com/yoshiofthewire/kydns-server/internal/store"
)

// recordingMux records the patterns Routes registers. http.ServeMux cannot be
// enumerated, so this is the only way to derive the table below from the
// router instead of hand-listing it.
type recordingMux struct{ patterns []string }

func (m *recordingMux) HandleFunc(pattern string, _ func(http.ResponseWriter, *http.Request)) {
	m.patterns = append(m.patterns, pattern)
}

var wildcard = regexp.MustCompile(`\{[^}]*\}`)

// registeredRoutes is every route the API registers, split into method and a
// concrete path with the wildcards filled in.
func registeredRoutes(t *testing.T) [][2]string {
	t.Helper()
	var rec recordingMux
	(&API{}).routes(&rec)
	out := make([][2]string, 0, len(rec.patterns))
	for _, p := range rec.patterns {
		method, path, ok := strings.Cut(p, " ")
		if !ok {
			t.Fatalf("route %q has no method, so the gate cannot be reasoned about", p)
		}
		out = append(out, [2]string{method, wildcard.ReplaceAllString(path, "1")})
	}
	return out
}

// replicaAPI builds a replica whose primary is addr.
func replicaAPI(t *testing.T, addr string) (*API, string) {
	t.Helper()
	return newAPIWithStatus(t, func() ReplicaStatus {
		return ReplicaStatus{Role: "replica", PrimaryAddr: addr}
	})
}

// replicaOf is replicaAPI wired up the way the daemon serves it.
func replicaOf(t *testing.T, addr string) (http.Handler, string) {
	t.Helper()
	a, tok := replicaAPI(t, addr)
	return a.Handler(), tok
}

// Every mutating admin route must be refused on a replica. The list is
// derived from the router, so a route added later fails this test rather
// than silently accepting writes a replica will overwrite on its next pull.
func TestEveryMutatingRouteIsRefusedOnAReplica(t *testing.T) {
	const primary = "10.0.0.2:8443"
	h, tok := replicaOf(t, primary)
	tested := 0
	for _, r := range registeredRoutes(t) {
		method, path := r[0], r[1]
		if method == http.MethodGet || method == http.MethodHead || writeExempt[path] {
			continue
		}
		tested++
		rec := do(t, h, method, path, tok, "{}")
		if rec.Code != http.StatusConflict {
			t.Errorf("%s %s on a replica = %d, want 409", method, path, rec.Code)
			continue
		}
		if !strings.Contains(rec.Body.String(), primary) {
			t.Errorf("%s %s body %q does not name the primary", method, path, rec.Body.String())
		}
	}
	if tested < 15 {
		t.Fatalf("only %d mutating routes enumerated; the table is not deriving from the router", tested)
	}
}

// The exemption set is pinned: a fifth path must be a deliberate edit here.
//
// PathSettings was added deliberately, by ruling P22. The DHCP settings are
// node-local - ApplySnapshot re-reads all eight dhcp_* columns out of the local
// row, so a pull cannot discard them - and refusing them left an operator
// unable to prepare a standby, which they discovered during a failover. The
// gate now decides only that the request may be answered; settings.Service
// decides what it may change, and refuses anything past those eight fields.
func TestWriteExemptIsExactlyFourPaths(t *testing.T) {
	want := map[string]bool{
		PathReplicaPairPeek: true,
		PathReplicaJoin:     true,
		PathReplicaPromote:  true,
		PathSettings:        true,
	}
	if !maps.Equal(writeExempt, want) {
		t.Fatalf("writeExempt = %v, want %v", writeExempt, want)
	}
}

// The three exempt paths reach their handler, both on a mux of this test's own
// and on the live API.
func TestExemptPathsPassTheGateOnAReplica(t *testing.T) {
	a, tok := replicaAPI(t, "10.0.0.2:8443")
	mux := http.NewServeMux()
	for _, p := range []string{PathReplicaPairPeek, PathReplicaJoin, PathReplicaPromote} {
		mux.HandleFunc("POST "+p, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
	}
	gated := a.WriteGate(mux)
	for _, p := range []string{PathReplicaPairPeek, PathReplicaJoin, PathReplicaPromote} {
		if rec := do(t, gated, "POST", p, tok, "{}"); rec.Code != http.StatusOK {
			t.Errorf("POST %s on a replica = %d, want 200: the exemption is not honoured", p, rec.Code)
		}
	}
	// On the live API all three have handlers of their own. None may be
	// answered by the gate: whatever comes back, it is not the read-only
	// refusal, and it is not a missing route.
	for _, p := range []string{PathReplicaPairPeek, PathReplicaJoin, PathReplicaPromote} {
		rec := do(t, a.Handler(), "POST", p, tok, "{}")
		if strings.Contains(rec.Body.String(), "read_only_replica") {
			t.Errorf("POST %s was refused by the gate it is exempt from: %s", p, rec.Body)
		}
		if rec.Code == http.StatusNotFound {
			t.Errorf("POST %s = 404: the exempt path has no route", p)
		}
	}
}

// A route the gate has never heard of must still be refused, or the gate is
// an enumeration of routes rather than a default-deny.
func TestUnknownMutatingRouteIsRefusedOnAReplica(t *testing.T) {
	a, tok := replicaAPI(t, "10.0.0.2:8443")
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/whatever", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	if rec := do(t, a.WriteGate(mux), "POST", "/api/v1/whatever", tok, ""); rec.Code != http.StatusConflict {
		t.Fatalf("POST /api/v1/whatever on a replica = %d, want 409", rec.Code)
	}
}

// A path with no route at all is refused too: the gate is outside the mux, so
// there is no way to reach a write it has not seen.
func TestUnroutedWriteIsRefusedOnAReplica(t *testing.T) {
	a, tok := replicaAPI(t, "10.0.0.2:8443")
	if rec := do(t, a.Handler(), "POST", "/api/v1/nonexistent", tok, ""); rec.Code != http.StatusConflict {
		t.Fatalf("POST /api/v1/nonexistent on a replica = %d, want 409", rec.Code)
	}
}

// The gate wraps the whole server handler, which the web transport shares.
// Task 3 gates the UI's own writes; a browser posting a form must get a page
// back, never this JSON, so the gate stops at the API prefix.
func TestWriteGateLeavesTheWebTransportAlone(t *testing.T) {
	a, tok := replicaAPI(t, "10.0.0.2:8443")
	mux := http.NewServeMux()
	mux.HandleFunc("POST /login", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	if rec := do(t, a.WriteGate(mux), "POST", "/login", tok, ""); rec.Code != http.StatusOK {
		t.Fatalf("POST /login on a replica = %d, want 200: the UI is not this gate's business", rec.Code)
	}
}

// The gate is outermost, so it must not answer a caller the API would have
// turned away: an anonymous write gets its 401 and learns nothing about where
// this node's primary lives.
func TestUnauthenticatedWriteOnAReplicaStillGets401(t *testing.T) {
	const primary = "10.0.0.2:8443"
	a, _ := replicaAPI(t, primary)
	for _, path := range []string{"/api/v1/services", "/api/v1/nonexistent"} {
		rec := do(t, a.Handler(), "POST", path, "", "{}")
		if path == "/api/v1/services" && rec.Code != http.StatusUnauthorized {
			t.Errorf("anonymous POST %s on a replica = %d, want 401", path, rec.Code)
		}
		if strings.Contains(rec.Body.String(), primary) {
			t.Errorf("anonymous POST %s leaks the primary address: %s", path, rec.Body)
		}
	}
}

// A replica's dashboard, stats and exports are its own and stay live.
func TestReadsAreUnaffectedOnAReplica(t *testing.T) {
	h, tok := replicaOf(t, "10.0.0.2:8443")
	for _, method := range []string{"GET", "HEAD"} {
		if rec := do(t, h, method, "/api/v1/services", tok, ""); rec.Code != http.StatusOK {
			t.Errorf("%s /api/v1/services on a replica = %d, want 200", method, rec.Code)
		}
	}
}

// Only a replica is refused. Every node reports a role, so "not a replica"
// has to mean accepted, not "not a role I recognise".
func TestEveryOtherRoleAcceptsWrites(t *testing.T) {
	const body = `{"name":"lan","subnets":["10.0.0.0/24"]}`
	for _, role := range []string{"primary", "standalone"} {
		h, tok := newReplicaAPI(t, ReplicaStatus{Role: role})
		if rec := do(t, h, "POST", "/api/v1/views", tok, body); rec.Code != http.StatusCreated {
			t.Errorf("POST /api/v1/views on a %s = %d: %s", role, rec.Code, rec.Body)
		}
	}
	h, tok := newAPI(t) // no replication wired at all
	if rec := do(t, h, "POST", "/api/v1/views", tok, body); rec.Code != http.StatusCreated {
		t.Errorf("POST /api/v1/views with no replication wired = %d: %s", rec.Code, rec.Body)
	}
}

// Promotion must take effect on the next request, not the next restart.
func TestGateReadsTheRolePerRequest(t *testing.T) {
	role := "replica"
	h, tok := newReplicaAPICallback(t, func() ReplicaStatus {
		return ReplicaStatus{Role: role, PrimaryAddr: "10.0.0.2:8443"}
	})
	body := `{"name":"lan","subnets":["10.0.0.0/24"]}`
	if rec := do(t, h, "POST", "/api/v1/views", tok, body); rec.Code != http.StatusConflict {
		t.Fatalf("POST as a replica = %d, want 409", rec.Code)
	}
	role = "primary"
	if rec := do(t, h, "POST", "/api/v1/views", tok, body); rec.Code != http.StatusCreated {
		t.Fatalf("POST after promotion = %d: %s", rec.Code, rec.Body)
	}
}

// replicaSettingsAPI is a replica with a real settings service behind it, wired
// the way serve.go does: the service reads the same role the gate does.
func replicaSettingsAPI(t *testing.T, role *string) (*testSrv, *settings.Service) {
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
	svc := settings.NewService(s, h, nil, func() bool { return *role == roleReplica })
	api := NewAPI(reg, nil, nil).WithSettings(svc).
		WithReplication(func() ReplicaStatus {
			return ReplicaStatus{Role: *role, PrimaryAddr: "10.0.0.2:8443"}
		})
	return &testSrv{h: api.Handler(), tok: tok}, svc
}

// dhcpPatch is a valid, DHCP-only partial update.
const dhcpPatch = `{"dhcp_enabled":true,"dhcp_interface":"eth0",` +
	`"dhcp_range_start":"192.168.1.100","dhcp_range_end":"192.168.1.200",` +
	`"dhcp_gateway":"192.168.1.1","dhcp_lease_seconds":3600}`

// What a replica may change through the API. The gate lets PATCH
// /api/v1/settings through so an operator can prepare a standby; the settings
// service is what holds the write to the eight node-local DHCP fields.
func TestAReplicaMayPatchTheDHCPSettings(t *testing.T) {
	role := roleReplica
	srv, svc := replicaSettingsAPI(t, &role)

	rec := srv.do(t, "PATCH", PathSettings, dhcpPatch)
	if rec.Code != http.StatusOK {
		t.Fatalf("a replica could not configure DHCP: %d %s", rec.Code, rec.Body)
	}
	cur, err := svc.Get()
	if err != nil {
		t.Fatal(err)
	}
	if !cur.DHCPEnabled || cur.DHCPInterface != "eth0" || cur.DHCPLeaseSeconds != 3600 {
		t.Fatalf("the patch did not land: %+v", cur)
	}
}

// The defect this task must not introduce. A partial update naming one DHCP key
// and one unrelated key is refused whole: neither half may land, or the
// exemption is not scoped at all.
func TestAReplicaCannotSmuggleANonDHCPKeyIntoADHCPPatch(t *testing.T) {
	role := roleReplica
	srv, svc := replicaSettingsAPI(t, &role)
	before, err := svc.Get()
	if err != nil {
		t.Fatal(err)
	}

	rec := srv.do(t, "PATCH", PathSettings, `{"dhcp_enabled":true,"ttl":120}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("a mixed patch on a replica = %d, want 409: %s", rec.Code, rec.Body)
	}
	var body errBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Error.Code != "read_only_replica" {
		t.Errorf("code = %q, want read_only_replica: %s", body.Error.Code, rec.Body)
	}

	after, err := svc.Get()
	if err != nil {
		t.Fatal(err)
	}
	if after.TTL != before.TTL {
		t.Errorf("ttl = %d, want %d: a replica changed a replicated setting", after.TTL, before.TTL)
	}
	if after.DHCPEnabled {
		t.Error("the DHCP half of a refused mixed patch was applied")
	}
}

// A patch that names no DHCP key at all is the plain case, and is refused for
// the same reason.
func TestAReplicaCannotPatchANonDHCPSetting(t *testing.T) {
	role := roleReplica
	srv, svc := replicaSettingsAPI(t, &role)
	for _, body := range []string{
		`{"ttl":120}`,
		`{"allow_query":["0.0.0.0/0"],"confirm_public":"0.0.0.0/0"}`,
		`{"private_domain":"lan.example"}`,
		`{"upstreams":["udp://9.9.9.9:53"]}`,
	} {
		if rec := srv.do(t, "PATCH", PathSettings, body); rec.Code != http.StatusConflict {
			t.Errorf("PATCH %s on a replica = %d, want 409: %s", body, rec.Code, rec.Body)
		}
	}
	cur, err := svc.Get()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cur, validStoredSettings()) {
		t.Errorf("the stored settings moved: %+v", cur)
	}
}

// Promotion widens the same endpoint on the next request, not the next restart.
func TestPromotionRestoresTheFullSettingsPatch(t *testing.T) {
	role := roleReplica
	srv, svc := replicaSettingsAPI(t, &role)
	if rec := srv.do(t, "PATCH", PathSettings, `{"ttl":120}`); rec.Code != http.StatusConflict {
		t.Fatalf("as a replica: %d %s", rec.Code, rec.Body)
	}
	role = "primary"
	if rec := srv.do(t, "PATCH", PathSettings, `{"ttl":120}`); rec.Code != http.StatusOK {
		t.Fatalf("after promotion: %d %s", rec.Code, rec.Body)
	}
	if cur, _ := svc.Get(); cur.TTL != 120 {
		t.Errorf("ttl = %d, want 120", cur.TTL)
	}
}

// The exemption moves this path outside the gate, and the gate is where the
// 401 for an anonymous caller used to be decided first. The token check on the
// handler is what still stops one.
func TestTheExemptSettingsPatchStillNeedsAToken(t *testing.T) {
	role := roleReplica
	srv, svc := replicaSettingsAPI(t, &role)
	rec := do(t, srv.h, "PATCH", PathSettings, "", dhcpPatch)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous PATCH on a replica = %d, want 401: %s", rec.Code, rec.Body)
	}
	if cur, _ := svc.Get(); cur.DHCPEnabled {
		t.Error("an anonymous patch configured DHCP")
	}
}
