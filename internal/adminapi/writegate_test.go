package adminapi

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
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

// replicaOf builds a replica whose primary is addr.
func replicaOf(t *testing.T, addr string) (http.Handler, string) {
	t.Helper()
	return newReplicaAPI(t, ReplicaStatus{Role: "replica", PrimaryAddr: addr})
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

// The exemption set is pinned: a fourth path must be a deliberate edit here.
func TestWriteExemptIsExactlyThreePaths(t *testing.T) {
	want := map[string]bool{
		PathReplicaPairPeek: true,
		PathReplicaJoin:     true,
		PathReplicaPromote:  true,
	}
	if len(writeExempt) != len(want) {
		t.Fatalf("writeExempt has %d paths, want %d: %v", len(writeExempt), len(want), writeExempt)
	}
	for p := range want {
		if !writeExempt[p] {
			t.Errorf("%s is not exempt", p)
		}
	}
}

// The three exempt paths reach their handler. Tasks 6 and 7 register them for
// real; registering them here through the same seam proves the exemption
// works before those handlers exist.
func TestExemptPathsPassTheGateOnAReplica(t *testing.T) {
	a := (&API{}).WithReplication(func() ReplicaStatus {
		return ReplicaStatus{Role: "replica", PrimaryAddr: "10.0.0.2:8443"}
	})
	mux := http.NewServeMux()
	for _, p := range []string{PathReplicaPairPeek, PathReplicaJoin, PathReplicaPromote} {
		a.gated(mux).HandleFunc("POST "+p, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
	}
	for _, p := range []string{PathReplicaPairPeek, PathReplicaJoin, PathReplicaPromote} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest("POST", p, nil))
		if rec.Code != http.StatusOK {
			t.Errorf("POST %s on a replica = %d, want 200: the exemption is not honoured", p, rec.Code)
		}
	}
	// Unregistered today, so the live API must 404 them rather than refuse them.
	h, tok := replicaOf(t, "10.0.0.2:8443")
	for _, p := range []string{PathReplicaPairPeek, PathReplicaJoin, PathReplicaPromote} {
		if rec := do(t, h, "POST", p, tok, "{}"); rec.Code != http.StatusNotFound {
			t.Errorf("POST %s = %d, want 404", p, rec.Code)
		}
	}
}

// A route the gate has never heard of must still be refused, or the gate is
// an enumeration of routes rather than a default-deny.
func TestUnknownMutatingRouteIsRefusedOnAReplica(t *testing.T) {
	a := (&API{}).WithReplication(func() ReplicaStatus {
		return ReplicaStatus{Role: "replica", PrimaryAddr: "10.0.0.2:8443"}
	})
	mux := http.NewServeMux()
	a.gated(mux).HandleFunc("POST /api/v1/whatever", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("POST", "/api/v1/whatever", nil))
	if rec.Code != http.StatusConflict {
		t.Fatalf("POST /api/v1/whatever on a replica = %d, want 409", rec.Code)
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
