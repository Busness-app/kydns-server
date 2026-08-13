package web

import (
	"maps"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

const testPrimaryAddr = "10.0.0.9:8443"

// replicaWeb wires a logged-in server behind the web write gate. The returned
// status is read per request, so a test can flip the role mid-test the way
// promotion does.
func replicaWeb(t *testing.T) (http.Handler, *http.ServeMux, *Server, *ReplicaStatus, *http.Cookie, string) {
	t.Helper()
	status := &ReplicaStatus{
		Role: "replica", PrimaryAddr: testPrimaryAddr, LastSyncUnix: time.Now().Unix(),
	}
	mux, srv := newWeb(t, func(o *Options) {
		o.Replication = func() ReplicaStatus { return *status }
	})
	h := srv.WriteGate(mux)
	setupAndLogin(t, h)
	c := loginCookie(t, h)
	sess, ok := srv.o.Sessions.Get(c.Value)
	if !ok {
		t.Fatal("no session")
	}
	return h, mux, srv, status, c, sess.CSRF
}

// recordingMux collects what registration asks for, so the route list under
// test is the router's own and cannot drift from it.
type recordingMux struct{ patterns []string }

func (m *recordingMux) Handle(p string, _ http.Handler) { m.patterns = append(m.patterns, p) }
func (m *recordingMux) HandleFunc(p string, _ func(http.ResponseWriter, *http.Request)) {
	m.patterns = append(m.patterns, p)
}

// registeredPostRoutes is every POST the web transport registers.
func registeredPostRoutes(t *testing.T, srv *Server) []string {
	t.Helper()
	var rec recordingMux
	srv.routes(&rec)
	var out []string
	for _, p := range rec.patterns {
		if path, ok := strings.CutPrefix(p, "POST "); ok {
			out = append(out, path)
		}
	}
	if len(out) < 15 {
		t.Fatalf("found only %d POST routes (%v); registration has changed shape", len(out), out)
	}
	return out
}

func TestReplicaRefusesEveryPostRoute(t *testing.T) {
	h, _, srv, _, c, csrf := replicaWeb(t)
	for _, path := range registeredPostRoutes(t, srv) {
		if webWriteExempt[path] {
			continue
		}
		rec := postForm(t, h, path, url.Values{"csrf_token": {csrf}}, c)
		if rec.Code != http.StatusConflict {
			t.Errorf("POST %s = %d, want 409 on a replica", path, rec.Code)
			continue
		}
		if !strings.Contains(rec.Body.String(), testPrimaryAddr) {
			t.Errorf("POST %s refusal does not name the primary:\n%s", path, rec.Body)
		}
	}
}

// The exempt set is this gate's whole attack surface, so it is pinned by value
// rather than by whatever the map happens to hold. Adding an entry here has to
// be a deliberate edit to this test.
func TestExemptSetIsExactlyTheFourNamedPaths(t *testing.T) {
	want := map[string]bool{
		PathSetup: true, PathLogin: true, PathLogout: true, PathPromote: true,
	}
	if !maps.Equal(webWriteExempt, want) {
		t.Fatalf("webWriteExempt = %v, want %v", webWriteExempt, want)
	}

	_, _, srv, _, _, _ := replicaWeb(t)
	registered := registeredPostRoutes(t, srv)
	// PathPromote is reserved, not yet registered: Task 8 adds its handler, and
	// TestPromoteIsNotRefusedByTheGate covers it in the meantime.
	for _, p := range []string{PathSetup, PathLogin, PathLogout} {
		if !slices.Contains(registered, p) {
			t.Errorf("exempt path %s is not a registered route: the exemption is dead or misspelled", p)
		}
	}
}

// Promotion is what ends a replica's read-only life, so the gate must never be
// what refuses it. The handler arrives in Task 8; what matters today is that a
// request to the path is not answered with a refusal.
func TestPromoteIsNotRefusedByTheGate(t *testing.T) {
	h, _, _, _, c, csrf := replicaWeb(t)
	rec := postForm(t, h, PathPromote, url.Values{"csrf_token": {csrf}}, c)
	if rec.Code == http.StatusConflict {
		t.Fatalf("POST %s = 409: a replica cannot be promoted through the only UI that offers it", PathPromote)
	}
	if rec.Code != http.StatusNotFound {
		t.Logf("POST %s = %d; the handler now exists, which is fine", PathPromote, rec.Code)
	}
}

// The promote button lives behind the login page, so an operator locked out of
// a replica's browser UI cannot recover it.
func TestLoginAndLogoutStillWorkOnAReplica(t *testing.T) {
	h, _, _, _, _, _ := replicaWeb(t)
	rec := postForm(t, h, "/login", url.Values{"password": {testPassword}}, nil)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /login on a replica = %d, want 303:\n%s", rec.Code, rec.Body)
	}
	c := sessionCookie(rec)
	if c == nil {
		t.Fatal("login on a replica handed out no session")
	}
	rec = postForm(t, h, "/logout", url.Values{"csrf_token": {csrfFor(t, h, c)}}, c)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /logout on a replica = %d, want 303:\n%s", rec.Code, rec.Body)
	}
}

// csrfFor reads the token out of a rendered page, which is the only place a
// browser gets it from either.
func csrfFor(t *testing.T, h http.Handler, c *http.Cookie) string {
	t.Helper()
	rec := get(t, h, "/", c)
	m := regexp.MustCompile(`name="csrf_token" value="([^"]+)"`).FindStringSubmatch(rec.Body.String())
	if m == nil {
		t.Fatalf("no csrf token on the dashboard:\n%s", rec.Body)
	}
	return m[1]
}

// The gate wraps the handler rather than the routes, so a POST nobody thought
// about is refused by default.
func TestReplicaRefusesAPostRouteAddedLater(t *testing.T) {
	h, mux, _, _, c, csrf := replicaWeb(t)
	mux.HandleFunc("POST /throwaway", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	rec := postForm(t, h, "/throwaway", url.Values{"csrf_token": {csrf}}, c)
	if rec.Code != http.StatusConflict {
		t.Fatalf("POST /throwaway = %d, want 409: a new route must be refused by default", rec.Code)
	}
}

var addRecordButton = regexp.MustCompile(`<button[^>]*\sdisabled[^>]*>Add record<`)

func TestReplicaRendersDisabledControlsNotHiddenOnes(t *testing.T) {
	h, _, _, _, c, _ := replicaWeb(t)
	body := get(t, h, "/records", c).Body.String()
	if !strings.Contains(body, ">Add record<") {
		t.Fatalf("the Add record button is missing; a control that vanishes reads as a bug:\n%s", body)
	}
	if !addRecordButton.MatchString(body) {
		t.Errorf("the Add record button is not disabled:\n%s", body)
	}
	if !strings.Contains(body, "Managed by "+testPrimaryAddr) {
		t.Errorf("the disabled control does not say who manages it:\n%s", body)
	}
}

var openFieldset = regexp.MustCompile(`<fieldset class="field-set"([^>]*)>`)

// A checkbox that moves when clicked and then cannot be saved reads as broken.
// One disabled fieldset per group takes every input inside it with it.
func TestReplicaDisablesTheSettingsFieldsets(t *testing.T) {
	h, _, _, status, c, _ := replicaWeb(t)
	body := get(t, h, "/settings", c).Body.String()
	if !strings.Contains(body, `name="log_queries"`) {
		t.Fatalf("the log_queries checkbox is missing; a control that vanishes reads as a bug:\n%s", body)
	}
	sets := openFieldset.FindAllStringSubmatch(body, -1)
	if len(sets) == 0 {
		t.Fatal("no field-set groups on the settings screen; the selector has gone stale")
	}
	for _, m := range sets {
		if !strings.Contains(m[1], "disabled") {
			t.Errorf("a settings field-set is editable on a replica: <fieldset class=\"field-set\"%s>", m[1])
		}
	}

	status.Role = "primary"
	body = get(t, h, "/settings", c).Body.String()
	for _, m := range openFieldset.FindAllStringSubmatch(body, -1) {
		if strings.Contains(m[1], "disabled") {
			t.Errorf("a primary renders its settings field-sets disabled: <fieldset class=\"field-set\"%s>", m[1])
		}
	}
}

func TestReplicaShowsStaleBannerPastSixtySeconds(t *testing.T) {
	h, _, _, status, c, _ := replicaWeb(t)

	status.LastSyncUnix = time.Now().Add(-10 * time.Second).Unix()
	if body := get(t, h, "/services", c).Body.String(); strings.Contains(body, staleBannerTitle) {
		t.Errorf("a replica synced 10s ago shows the stale banner:\n%s", body)
	}

	status.LastSyncUnix = time.Now().Add(-61 * time.Second).Unix()
	for _, path := range []string{"/", "/services", "/records", "/settings"} {
		body := get(t, h, path, c).Body.String()
		if !strings.Contains(body, staleBannerTitle) {
			t.Errorf("GET %s shows no stale banner 61s after the last sync:\n%s", path, body)
		}
		if !strings.Contains(body, testPrimaryAddr) {
			t.Errorf("GET %s stale banner does not name the primary", path)
		}
	}
}

// Reads are a replica's own and stay live.
func TestReplicaDashboardStillRenders(t *testing.T) {
	h, _, _, _, c, _ := replicaWeb(t)
	for _, path := range []string{"/", "/services", "/records", "/blacklists", "/settings", "/stats.json"} {
		rec := get(t, h, path, c)
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s on a replica = %d, want 200", path, rec.Code)
		}
	}
	if body := get(t, h, "/", c).Body.String(); !strings.Contains(body, "Queries") {
		t.Errorf("the replica dashboard is not rendering its own numbers:\n%s", body)
	}
}

func TestPrimaryRendersNormally(t *testing.T) {
	h, _, _, status, c, csrf := replicaWeb(t)
	status.Role = "primary"
	status.PrimaryAddr = ""

	rec := postForm(t, h, "/records/new", url.Values{
		"name": {"printer.home.arpa."}, "type": {"A"}, "value": {"192.168.1.50"},
		"csrf_token": {csrf},
	}, c)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /records/new on a primary = %d, want 303:\n%s", rec.Code, rec.Body)
	}
	body := get(t, h, "/records", c).Body.String()
	if addRecordButton.MatchString(body) {
		t.Error("a primary renders the Add record button disabled")
	}
	if strings.Contains(body, "Managed by") || strings.Contains(body, staleBannerTitle) {
		t.Error("a primary renders replica chrome")
	}
}
