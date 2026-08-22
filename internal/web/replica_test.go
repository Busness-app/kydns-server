package web

import (
	"maps"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/yoshiofthewire/kydns-server/internal/adminapi"
	"github.com/yoshiofthewire/kydns-server/internal/discovery/dhcp"
	"github.com/yoshiofthewire/kydns-server/internal/settings"
	"github.com/yoshiofthewire/kydns-server/internal/store"
)

const testPrimaryAddr = "10.0.0.9:8443"

// replicaWeb wires a logged-in server behind the web write gate. The returned
// status is read per request, so a test can flip the role mid-test the way
// promotion does. Extra tweaks are applied after the role, so a test can seed
// the state a screen needs before it renders the controls under test.
func replicaWeb(t *testing.T, tweak ...func(*Options)) (http.Handler, *http.ServeMux, *Server, *ReplicaStatus, *http.Cookie, string) {
	t.Helper()
	status := &ReplicaStatus{
		Role: "replica", PrimaryAddr: testPrimaryAddr, LastSyncUnix: time.Now().Unix(),
	}
	mux, srv := newWeb(t, append([]func(*Options){func(o *Options) {
		o.Replication = func() ReplicaStatus { return *status }
	}}, tweak...)...)
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
//
// PathJoin was added deliberately: the gate refuses writes because the next
// pull discards them, and pairing is the write that creates the pull. Without
// it an unpaired replica has no way to start and a removed one no way back.
//
// PathDHCPSettings and PathDHCPSuggest were added deliberately too, by ruling
// P22. The DHCP settings are node-local - ApplySnapshot re-reads all eight
// dhcp_* columns out of the local row, so a pull cannot discard them - and
// refusing them left an operator unable to prepare a standby, which they found
// out during a failover. Suggest writes nothing at all; it reads the interface
// and re-renders the form beside Save.
//
// What a replica may actually change is not decided here. This gate decides
// only that the post is answered; settings.Service refuses any write reaching
// past the eight DHCP fields, which is why /dhcp/reserve - a service write, and
// replicated - is not on this list.
func TestExemptSetIsExactlyTheSevenNamedPaths(t *testing.T) {
	want := map[string]bool{
		PathSetup: true, PathLogin: true, PathLogout: true,
		PathPromote: true, PathJoin: true,
		PathDHCPSettings: true, PathDHCPSuggest: true,
	}
	if !maps.Equal(webWriteExempt, want) {
		t.Fatalf("webWriteExempt = %v, want %v", webWriteExempt, want)
	}

	_, _, srv, _, _, _ := replicaWeb(t)
	registered := registeredPostRoutes(t, srv)
	for p := range want {
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

// The threshold is the puller's, so the screen renders its verdict rather than
// timing the sync again with its own constant.
func TestReplicaShowsStaleBannerOnTheStaleFlag(t *testing.T) {
	h, _, _, status, c, _ := replicaWeb(t)

	status.LastSyncUnix = time.Now().Add(-10 * time.Second).Unix()
	if body := get(t, h, "/services", c).Body.String(); strings.Contains(body, staleBannerTitle) {
		t.Errorf("a replica the puller calls fresh shows the stale banner:\n%s", body)
	}

	status.Stale = true
	status.LastSyncUnix = time.Now().Add(-61 * time.Second).Unix()
	for _, path := range []string{"/", "/services", "/records", "/settings"} {
		body := get(t, h, path, c).Body.String()
		if !strings.Contains(body, staleBannerTitle) {
			t.Errorf("GET %s shows no stale banner for a stale replica:\n%s", path, body)
		}
		if !strings.Contains(body, testPrimaryAddr) {
			t.Errorf("GET %s stale banner does not name the primary", path)
		}
	}
}

// The failure this closes: the operator removes this replica on the primary,
// every poll is refused, and the only thing on the screen says to check that a
// primary which is up and answering is reachable.
func TestStaleBannerCarriesTheLastError(t *testing.T) {
	h, _, _, status, c, _ := replicaWeb(t)
	const unlinked = "primary claims node \"\" but this node is pinned to fp-orchard"

	status.Stale = true
	status.LastError = unlinked
	status.LastSyncUnix = time.Now().Add(-61 * time.Second).Unix()
	body := get(t, h, "/services", c).Body.String()
	if !strings.Contains(body, "pinned to fp-orchard") {
		t.Errorf("the banner does not report why the last poll failed:\n%s", body)
	}
	// The wrong instruction, and the one an operator would act on first.
	if strings.Contains(body, "is reachable from this node") {
		t.Errorf("a refused replica is told to check reachability:\n%s", body)
	}
	// Where to pair, not which command: the Replication screen now carries the
	// form, so a browser-only operator is no longer sent to a terminal.
	if !strings.Contains(body, "Replication screen") {
		t.Errorf("the banner does not say how to pair this node again:\n%s", body)
	}

	// The same error on the replication screen, which is where an operator goes
	// once the banner has sent them there. Matched on the row's own label: the
	// banner renders on this page too and carries the same text, so the value
	// alone would be satisfied by a screen that shows nothing itself.
	page := get(t, h, "/replication", c).Body.String()
	if !strings.Contains(page, "Last error") || !strings.Contains(page, "pinned to fp-orchard") {
		t.Errorf("the replication screen has no last-error row of its own:\n%s", page)
	}

	// Without an error the reachability advice is still the right one.
	status.LastError = ""
	if body := get(t, h, "/services", c).Body.String(); !strings.Contains(body, "is reachable from this node") {
		t.Errorf("an unreachable primary loses the advice to check the network:\n%s", body)
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

// The failure this task exists to end: an operator could not prepare a standby,
// and found out during a failover. The DHCP settings are node-local, so a
// replica holds its own and the next pull preserves them.
func TestReplicaMaySaveTheDHCPForm(t *testing.T) {
	h, _, srv, _, c, csrf := replicaWeb(t)

	rec := postForm(t, h, PathDHCPSettings, dhcpFormValues(csrf), c)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST %s on a replica = %d, want 303:\n%s", PathDHCPSettings, rec.Code, rec.Body)
	}
	cur, err := srv.o.Settings.Get()
	if err != nil {
		t.Fatal(err)
	}
	if !cur.DHCPEnabled || cur.DHCPInterface != "eth0" || cur.DHCPLeaseSeconds != 86400 {
		t.Fatalf("the save did not reach the settings: %+v", cur)
	}
	// The replicated half is untouched, because the write never carried it.
	if cur.PrivateDomain != testSettings().PrivateDomain || cur.TTL != testSettings().TTL {
		t.Errorf("a DHCP save moved a replicated setting: %+v", cur)
	}
}

// buttonTag is the opening tag of the button labelled label, which sits just
// before it. Fatal rather than empty when the label is missing: a selector that
// silently matches nothing is how an assertion stops being one.
func buttonTag(t *testing.T, body, label string) string {
	t.Helper()
	i := strings.Index(body, label)
	if i < 0 {
		t.Fatalf("the %s button is missing from the page:\n%s", label, body)
	}
	open := strings.LastIndex(body[:i], "<button")
	if open < 0 {
		t.Fatalf("no opening tag before %s; the selector has gone stale", label)
	}
	return body[open:i]
}

// A form whose controls are disabled is a form an operator cannot use, so the
// exemption would be unreachable through the only UI that offers it. Reserve is
// the control beside it that must stay disabled: it saves a service, which is
// replicated.
//
// The lease is seeded because the Reserve button lives in the lease-row loop.
// Without one the row never renders and this test asserted nothing about it.
func TestTheDHCPFormIsEditableOnAReplicaButReserveIsNot(t *testing.T) {
	h, _, _, _, c, _ := replicaWeb(t, withDHCP(fakeDHCP{running: true}), func(o *Options) {
		o.Leases = func() []dhcp.Lease {
			return []dhcp.Lease{{
				Hostname: "laptop", IP: "192.168.1.50", MAC: "aa:bb:cc:dd:ee:01",
				Expires: time.Now().Add(time.Hour),
			}}
		}
	})
	body := get(t, h, "/dhcp", c).Body.String()
	for _, label := range []string{">Save<", ">Fill in from this interface<"} {
		if tag := buttonTag(t, body, label); strings.Contains(tag, "disabled") {
			t.Errorf("the %s button is disabled on a replica: %s", label, tag)
		}
	}
	tag := buttonTag(t, body, ">Reserve<")
	if !strings.Contains(tag, "disabled") {
		t.Errorf("the Reserve button is editable on a replica: %s", tag)
	}
	if !strings.Contains(tag, "Managed by "+testPrimaryAddr) {
		t.Errorf("the disabled Reserve button does not say who manages it: %s", tag)
	}
}

// storedSettings is the persisted row, read past the in-memory holder: a write
// that reached the database and still looked refused would leave the holder
// untouched, and a test reading the holder would call that "wrote nothing".
func storedSettings(t *testing.T, srv *Server) store.Settings {
	t.Helper()
	v, ok, err := srv.o.Store.Settings()
	if err != nil || !ok {
		t.Fatalf("reading the stored settings: %v (ok=%v)", err, ok)
	}
	return v
}

// Suggest fills the form in and saves nothing, which is why it is exempt.
func TestSuggestOnAReplicaAnswersAndWritesNothing(t *testing.T) {
	h, _, srv, _, c, csrf := replicaWeb(t)
	before := storedSettings(t, srv)
	rec := postForm(t, h, PathDHCPSuggest, dhcpFormValues(csrf), c)
	if rec.Code == http.StatusConflict {
		t.Fatalf("POST %s on a replica = 409: the wizard is refused beside a Save that is not", PathDHCPSuggest)
	}
	if after := storedSettings(t, srv); !reflect.DeepEqual(before, after) {
		t.Errorf("the suggest button wrote:\nbefore %+v\nafter  %+v", before, after)
	}
}

// The two transports answer the same refusal the same way. A replica may save
// this form, so the only way it is refused as read-only is a pull landing
// between the form read and the write — an operator who did nothing wrong, and
// who needs the address of the box the rest of the settings live on. The race
// itself cannot be staged from a test: liveSettings and Set read the same
// holder inside one request, with nothing in between to inject into.
func TestTheDHCPSaveRefusalMatchesTheAPI(t *testing.T) {
	_, _, srv, status, _, _ := replicaWeb(t)

	code, msg := srv.dhcpSaveRefusal(settings.ErrReadOnlyReplica)
	if code != http.StatusConflict {
		t.Errorf("a read-only refusal on the DHCP form = %d, want the 409 the API answers with", code)
	}
	// Against adminapi's own clause, not a copy of its wording: a copy here
	// would let the two transports drift apart while both tests stayed green.
	if !strings.HasSuffix(msg, adminapi.ManagedOn(testPrimaryAddr)) {
		t.Errorf("the refusal does not end the way the API's does: %q", msg)
	}
	if !strings.Contains(msg, testPrimaryAddr) {
		t.Errorf("the refusal does not name the primary: %q", msg)
	}

	// An unpaired replica knows no address. The settings error already ends
	// "on its primary", so there is nothing to append and nothing to repeat.
	status.PrimaryAddr = ""
	if _, msg := srv.dhcpSaveRefusal(settings.ErrReadOnlyReplica); strings.Contains(msg, "make this change on") {
		t.Errorf("the refusal says where twice when it knows no address: %q", msg)
	}
	status.PrimaryAddr = testPrimaryAddr

	// A validation failure is the operator's own input and stays a 400.
	code, _ = srv.dhcpSaveRefusal(errSettingsUnread)
	if code != http.StatusBadRequest {
		t.Errorf("a plain rejection = %d, want 400", code)
	}

	// Promotion ends the refusal, so nothing here is pinned to being a replica.
	status.Role = "primary"
	status.PrimaryAddr = ""
	if _, msg := srv.dhcpSaveRefusal(settings.ErrReadOnlyReplica); strings.Contains(msg, testPrimaryAddr) {
		t.Errorf("a promoted node still names a primary: %q", msg)
	}
}

// The neighbouring DHCP post is a service write, which is replicated: it stays
// refused, and the sweep above would not say so on its own if it were exempted.
func TestReserveIsStillRefusedOnAReplica(t *testing.T) {
	h, _, _, _, c, csrf := replicaWeb(t)
	rec := postForm(t, h, "/dhcp/reserve",
		url.Values{"csrf_token": {csrf}, "ip": {"192.168.1.50"}}, c)
	if rec.Code != http.StatusConflict {
		t.Fatalf("POST /dhcp/reserve on a replica = %d, want 409:\n%s", rec.Code, rec.Body)
	}
}

// Promotion widens the form to the whole row, on the next request rather than
// the next restart.
func TestPromotionRestoresTheServerSettingsForm(t *testing.T) {
	h, _, srv, status, c, csrf := replicaWeb(t)
	if rec := postForm(t, h, "/settings/server", validForm(csrf), c); rec.Code != http.StatusConflict {
		t.Fatalf("POST /settings/server on a replica = %d, want 409", rec.Code)
	}
	status.Role = "primary"
	if rec := postForm(t, h, "/settings/server", validForm(csrf), c); rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /settings/server after promotion = %d, want 303:\n%s", rec.Code, rec.Body)
	}
	if _, err := srv.o.Settings.Get(); err != nil {
		t.Fatal(err)
	}
}
