package adminapi

import (
	"net/http"
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
// real; registering them here behind the same gate proves the exemption works
// before those handlers exist.
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
	// Unregistered today, so the live API must 404 them rather than refuse them.
	for _, p := range []string{PathReplicaPairPeek, PathReplicaJoin, PathReplicaPromote} {
		if rec := do(t, a.Handler(), "POST", p, tok, "{}"); rec.Code != http.StatusNotFound {
			t.Errorf("POST %s = %d, want 404", p, rec.Code)
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
