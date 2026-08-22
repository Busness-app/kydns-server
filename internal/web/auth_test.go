package web

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/yoshiofthewire/kydns-server/internal/adminapi"
	"github.com/yoshiofthewire/kydns-server/internal/auth"
	"github.com/yoshiofthewire/kydns-server/internal/config"
	"github.com/yoshiofthewire/kydns-server/internal/dnsserver"
	"github.com/yoshiofthewire/kydns-server/internal/policy"
	"github.com/yoshiofthewire/kydns-server/internal/registry"
	"github.com/yoshiofthewire/kydns-server/internal/settings"
	"github.com/yoshiofthewire/kydns-server/internal/store"
)

const testPassword = "a-good-password"

// testSettings is a valid, LAN-only starting point for the settings service.
func testSettings() store.Settings {
	return store.Settings{
		PrivateDomain: "home.arpa",
		Upstreams:     []string{"tls://1.1.1.1:853"},
		AllowQuery:    []string{"192.168.0.0/16"},
		TTL:           60, CacheMinTTL: 5, CacheMaxTTL: 3600,
		NegativeMaxTTL: 300, CacheEntries: 10000,
		DiscoveryInterval: 30, HealthInterval: 30, HealthTimeout: 5, HealthWorkers: 8,
	}
}

// testConfig is the file-owned half: the keys that are read once at startup.
func testConfig() *config.Config {
	return &config.Config{
		DataDir: "/var/lib/kydns",
		DNS:     config.DNSConfig{Listen: ":53"},
		Admin:   config.AdminConfig{Listen: "127.0.0.1:8053"},
	}
}

// newSettings wires a settings service over st, seeded with testSettings.
func newSettings(t *testing.T, st *store.Store) *settings.Service {
	t.Helper()
	if err := st.PutSettings(testSettings()); err != nil {
		t.Fatal(err)
	}
	h := settings.NewHolder(func() (store.Settings, error) {
		v, _, err := st.Settings()
		return v, err
	})
	if err := h.Rebuild(); err != nil {
		t.Fatal(err)
	}
	return settings.NewService(st, h, nil)
}

func newWeb(t *testing.T, tweak ...func(*Options)) (*http.ServeMux, *Server) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "kydns.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	reg := registry.New(st, "home.arpa.", func() error { return nil })
	acl := dnsserver.NewACL([]netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")})
	cache := dnsserver.NewCache(100, 5, 3600, 300)
	ph := policy.NewHolder(func() (store.BlacklistSettings, []store.BlacklistList, []store.BlacklistRule, error) {
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
	if err := policy.SeedBuiltins(st); err != nil {
		t.Fatal(err)
	}
	if err := ph.Rebuild(); err != nil {
		t.Fatal(err)
	}
	pol := policy.NewService(st, ph, policy.NewRefresher(st, policy.NewFetcher(2*time.Second), ph, nil), nil)
	// One settings service behind both, as serve.go wires it: the DHCP tab
	// reads the chosen interface through the API.
	set := newSettings(t, st)
	o := Options{
		Store:      st,
		Registry:   reg,
		API:        adminapi.NewAPI(reg, acl, cache).WithPolicy(pol).WithSettings(set),
		Sessions:   auth.NewSessions(time.Hour, 12*time.Hour),
		Backoff:    auth.NewBackoff(),
		ACL:        acl,
		Cache:      cache,
		Policy:     pol,
		Settings:   set,
		SetupToken: "setup-me",
	}
	for _, f := range tweak {
		f(&o)
	}
	srv := New(o)
	mux := http.NewServeMux()
	srv.Routes(mux)
	return mux, srv
}

// setAllowTailscale flips the live setting through the one write path.
func setAllowTailscale(t *testing.T, srv *Server, on bool) {
	t.Helper()
	v, err := srv.o.Settings.Get()
	if err != nil {
		t.Fatal(err)
	}
	v.AllowTailscale = on
	if err := srv.o.Settings.Set(v, ""); err != nil {
		t.Fatal(err)
	}
}

func get(t *testing.T, h http.Handler, path string, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func postForm(t *testing.T, h http.Handler, path string, form url.Values, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func sessionCookie(rec *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == auth.CookieName && c.Value != "" {
			return c
		}
	}
	return nil
}

func setupAndLogin(t *testing.T, h http.Handler) {
	t.Helper()
	rec := postForm(t, h, "/setup", url.Values{
		"token": {"setup-me"}, "password": {testPassword}, "confirm": {testPassword},
	}, nil)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("setup = %d: %s", rec.Code, rec.Body)
	}
}

func loginCookie(t *testing.T, h http.Handler) *http.Cookie {
	t.Helper()
	rec := postForm(t, h, "/login", url.Values{"password": {testPassword}}, nil)
	c := sessionCookie(rec)
	if c == nil {
		t.Fatalf("no session cookie after login: %d %s", rec.Code, rec.Body)
	}
	return c
}

func itoa(i int64) string { return strconv.FormatInt(i, 10) }

// Before an admin exists, every route funnels to /setup.
func TestUnsetupRedirectsToSetup(t *testing.T) {
	h, _ := newWeb(t)
	for _, path := range []string{"/", "/services", "/records", "/settings", "/login"} {
		rec := get(t, h, path, nil)
		if rec.Code != http.StatusSeeOther {
			t.Errorf("GET %s = %d, want 303 to /setup", path, rec.Code)
			continue
		}
		if loc := rec.Header().Get("Location"); loc != "/setup" {
			t.Errorf("GET %s redirected to %q, want /setup", path, loc)
		}
	}
}

func TestSetupRequiresTheToken(t *testing.T) {
	h, _ := newWeb(t)
	rec := postForm(t, h, "/setup", url.Values{
		"token": {"wrong"}, "password": {testPassword}, "confirm": {testPassword},
	}, nil)
	if rec.Code == http.StatusSeeOther {
		t.Fatal("setup succeeded with the wrong token")
	}
	if !strings.Contains(strings.ToLower(rec.Body.String()), "token") {
		t.Errorf("body does not mention the token problem:\n%s", rec.Body)
	}
}

func TestSetupRejectsMismatchedConfirmation(t *testing.T) {
	h, _ := newWeb(t)
	rec := postForm(t, h, "/setup", url.Values{
		"token": {"setup-me"}, "password": {"one-good-password"}, "confirm": {"another-password"},
	}, nil)
	if rec.Code == http.StatusSeeOther {
		t.Error("setup accepted mismatched passwords")
	}
}

func TestSetupRejectsShortPassword(t *testing.T) {
	h, _ := newWeb(t)
	rec := postForm(t, h, "/setup", url.Values{
		"token": {"setup-me"}, "password": {"short"}, "confirm": {"short"},
	}, nil)
	if rec.Code == http.StatusSeeOther {
		t.Error("setup accepted a password below the minimum length")
	}
}

func TestSetupThenLogin(t *testing.T) {
	h, _ := newWeb(t)
	rec := postForm(t, h, "/setup", url.Values{
		"token": {"setup-me"}, "password": {testPassword}, "confirm": {testPassword},
	}, nil)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("setup = %d: %s", rec.Code, rec.Body)
	}
	if sessionCookie(rec) == nil {
		t.Error("setup did not log the operator in")
	}
	// Setup is single-use.
	rec = get(t, h, "/setup", nil)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Errorf("GET /setup after setup = %d %q, want a redirect to /login",
			rec.Code, rec.Header().Get("Location"))
	}

	rec = postForm(t, h, "/login", url.Values{"password": {testPassword}}, nil)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("login = %d: %s", rec.Code, rec.Body)
	}
	c := sessionCookie(rec)
	if c == nil {
		t.Fatal("login set no session cookie")
	}
	if !c.HttpOnly {
		t.Error("session cookie is not HttpOnly")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Error("session cookie is not SameSite=Lax")
	}
}

// A second setup attempt must not be able to reset the password.
func TestSetupIsSingleUse(t *testing.T) {
	h, srv := newWeb(t)
	setupAndLogin(t, h)
	rec := postForm(t, h, "/setup", url.Values{
		"token": {"setup-me"}, "password": {"attacker-password"}, "confirm": {"attacker-password"},
	}, nil)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Errorf("second setup = %d %q, want a redirect to /login", rec.Code, rec.Header().Get("Location"))
	}
	hash, err := srv.o.Store.AdminHash()
	if err != nil {
		t.Fatal(err)
	}
	if auth.VerifyPassword(hash, "attacker-password") {
		t.Error("a second setup POST replaced the admin password")
	}
}

func TestLoginRejectsWrongPassword(t *testing.T) {
	h, _ := newWeb(t)
	setupAndLogin(t, h)
	rec := postForm(t, h, "/login", url.Values{"password": {"wrong"}}, nil)
	if sessionCookie(rec) != nil {
		t.Error("a failed login issued a session cookie")
	}
	if rec.Code == http.StatusSeeOther {
		t.Error("a failed login redirected as though it succeeded")
	}
}

func TestProtectedRouteNeedsSession(t *testing.T) {
	h, _ := newWeb(t)
	setupAndLogin(t, h)
	rec := get(t, h, "/services", nil)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Errorf("unauthenticated /services = %d %q, want a redirect to /login",
			rec.Code, rec.Header().Get("Location"))
	}
}

func TestLogoutDestroysSession(t *testing.T) {
	h, srv := newWeb(t)
	setupAndLogin(t, h)
	c := loginCookie(t, h)
	if get(t, h, "/services", c).Code != http.StatusOK {
		t.Fatal("session did not grant access")
	}
	sess, _ := srv.o.Sessions.Get(c.Value)
	rec := postForm(t, h, "/logout", url.Values{"csrf_token": {sess.CSRF}}, c)
	cleared := rec.Result().Cookies()[0]
	if cleared.Name != auth.CookieName || cleared.MaxAge != -1 || !cleared.HttpOnly ||
		cleared.SameSite != http.SameSiteLaxMode {
		t.Errorf("logout cookie = %+v, want a protected deletion cookie", cleared)
	}
	if got := get(t, h, "/services", c).Code; got != http.StatusSeeOther {
		t.Errorf("after logout /services = %d, want a redirect", got)
	}
}

// A POST without the session's CSRF token must be rejected.
func TestCSRFRequiredOnPost(t *testing.T) {
	h, srv := newWeb(t)
	setupAndLogin(t, h)
	c := loginCookie(t, h)

	bad := postForm(t, h, "/services/new", url.Values{
		"name": {"kypost"}, "address": {"192.168.1.20"},
	}, c)
	if bad.Code != http.StatusForbidden {
		t.Errorf("POST without a CSRF token = %d, want 403", bad.Code)
	}

	sess, ok := srv.o.Sessions.Get(c.Value)
	if !ok {
		t.Fatal("session vanished")
	}
	good := postForm(t, h, "/services/new", url.Values{
		"name": {"kypost"}, "address": {"192.168.1.20"}, "csrf_token": {sess.CSRF},
	}, c)
	if good.Code == http.StatusForbidden {
		t.Errorf("POST with a valid CSRF token = 403: %s", good.Body)
	}
}

// An anonymous POST redirects to login rather than leaking a 403 that implies
// the route exists behind a valid session.
func TestCSRFMiddlewareRedirectsAnonymous(t *testing.T) {
	h, _ := newWeb(t)
	setupAndLogin(t, h)
	rec := postForm(t, h, "/services/new", url.Values{"name": {"x"}}, nil)
	if rec.Code != http.StatusSeeOther {
		t.Errorf("anonymous POST = %d, want a redirect to /login", rec.Code)
	}
}

// The two POSTs above pin one route. This pins every one the router registers,
// including any added later: a handler wired straight into the mux instead of
// through requireCSRF changes network configuration on an unauthenticated POST.
// Setup and login are the deliberate pre-session pair, named rather than
// skipped by pattern.
func TestEveryPostRouteRequiresSessionAndCSRF(t *testing.T) {
	h, srv := newWeb(t)
	setupAndLogin(t, h)
	c := loginCookie(t, h)
	preSession := map[string]bool{PathSetup: true, PathLogin: true}
	for _, path := range registeredPostRoutes(t, srv) {
		if preSession[path] {
			continue
		}
		if rec := postForm(t, h, path, url.Values{}, c); rec.Code != http.StatusForbidden {
			t.Errorf("POST %s with a session but no CSRF token = %d, want 403", path, rec.Code)
		}
		if rec := postForm(t, h, path, url.Values{}, nil); rec.Code != http.StatusSeeOther {
			t.Errorf("anonymous POST %s = %d, want a redirect to /login", path, rec.Code)
		}
	}
}

func fakeIDToken(sub, username, email, role string) string {
	claims := map[string]any{
		"sub":      sub,
		"username": username,
		"email":    email,
		"role":     role,
		"iss":      "https://auth.urlxl.com",
	}
	claimsJSON, _ := json.Marshal(claims)
	encodedClaims := base64.RawURLEncoding.EncodeToString(claimsJSON)
	return "header." + encodedClaims + ".signature"
}

func TestSSOLoginButtonShownWhenEnabled(t *testing.T) {
	h, srv := newWeb(t)
	setupAndLogin(t, h)

	// Disabled by default: login page doesn't show SSO button
	rec := get(t, h, "/login", nil)
	if strings.Contains(rec.Body.String(), "Sign in with KySignOn") {
		t.Error("SSO button shown when SSO is disabled")
	}

	// Enable SSO
	_ = srv.o.Store.SetSSOSettings(store.SSOSettings{
		Enabled:   true,
		IssuerURL: "https://auth.urlxl.com",
		ClientID:  "kydns",
	})

	rec = get(t, h, "/login", nil)
	if !strings.Contains(rec.Body.String(), "Sign in with KySignOn") {
		t.Error("SSO button missing when SSO is enabled")
	}
}

func TestSSOGetLoginSetsPKCEAndRedirects(t *testing.T) {
	h, srv := newWeb(t)
	setupAndLogin(t, h)
	_ = srv.o.Store.SetSSOSettings(store.SSOSettings{
		Enabled:   true,
		IssuerURL: "https://auth.urlxl.com",
		ClientID:  "kydns",
	})

	req := httptest.NewRequest("GET", "/auth/sso/login", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303 redirect", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://auth.urlxl.com/oauth/authorize") {
		t.Errorf("unexpected redirect: %s", loc)
	}

	// Verify cookies were set
	var stateCookie, verifierCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == cookieSSOState {
			stateCookie = c
		}
		if c.Name == cookieSSOVerifier {
			verifierCookie = c
		}
	}
	if stateCookie == nil || verifierCookie == nil {
		t.Fatalf("missing PKCE / state cookies")
	}
}

func TestSSOCallbackRejectsNonAdminRole(t *testing.T) {
	mockSSOServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "tok",
			"id_token":     fakeIDToken("sub-1", "regular_bob", "bob@urlxl.com", "user"),
			"token_type":   "Bearer",
		})
	}))
	defer mockSSOServer.Close()

	h, srv := newWeb(t)
	setupAndLogin(t, h)
	_ = srv.o.Store.SetSSOSettings(store.SSOSettings{
		Enabled:   true,
		IssuerURL: mockSSOServer.URL,
		ClientID:  "kydns",
	})

	req := httptest.NewRequest("GET", "/auth/sso/callback?code=mock_code&state=test_state", nil)
	req.AddCookie(&http.Cookie{Name: cookieSSOState, Value: "test_state"})
	req.AddCookie(&http.Cookie{Name: cookieSSOVerifier, Value: "test_verifier"})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("callback status = %d, want 403 Forbidden for non-admin", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "requires an Administrator account") {
		t.Errorf("unexpected body: %s", rec.Body.String())
	}
}

func TestSSOCallbackAutoLinksAdminAndLogsIn(t *testing.T) {
	mockSSOServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "tok",
			"id_token":     fakeIDToken("sso-sub-admin-999", "admin_yoshi", "yoshi@urlxl.com", "admin"),
			"token_type":   "Bearer",
		})
	}))
	defer mockSSOServer.Close()

	h, srv := newWeb(t)
	setupAndLogin(t, h)
	_ = srv.o.Store.SetSSOSettings(store.SSOSettings{
		Enabled:   true,
		IssuerURL: mockSSOServer.URL,
		ClientID:  "kydns",
	})

	req := httptest.NewRequest("GET", "/auth/sso/callback?code=mock_code&state=test_state", nil)
	req.AddCookie(&http.Cookie{Name: cookieSSOState, Value: "test_state"})
	req.AddCookie(&http.Cookie{Name: cookieSSOVerifier, Value: "test_verifier"})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303 redirect", rec.Code)
	}
	if rec.Header().Get("Location") != "/" {
		t.Errorf("redirect = %s, want /", rec.Header().Get("Location"))
	}

	// Verify session cookie was set
	var sessCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == auth.CookieName && c.Value != "" {
			sessCookie = c
		}
	}
	if sessCookie == nil {
		t.Fatalf("expected session cookie set after SSO login")
	}

	// Verify AdminIdentity was auto-linked
	ident, err := srv.o.Store.AdminIdentity()
	if err != nil || ident.SSOSub != "sso-sub-admin-999" || ident.SSOUsername != "admin_yoshi" {
		t.Errorf("unexpected linked identity: %+v, err: %v", ident, err)
	}
}

func TestSSOSettingsSaveAndUnlink(t *testing.T) {
	h, srv := newWeb(t)
	setupAndLogin(t, h)
	c := loginCookie(t, h)
	sess, _ := srv.o.Sessions.Get(c.Value)

	// Save settings
	rec := postForm(t, h, "/settings/sso", url.Values{
		"csrf_token":    {sess.CSRF},
		"enabled":       {"1"},
		"issuer_url":    {"https://auth.urlxl.com"},
		"client_id":     {"kydns-prod"},
		"client_secret": {"sec123"},
	}, c)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want redirect", rec.Code)
	}

	sso, _ := srv.o.Store.SSOSettings()
	if !sso.Enabled || sso.ClientID != "kydns-prod" || sso.ClientSecret != "sec123" {
		t.Errorf("unexpected SSOSettings: %+v", sso)
	}

	// Link admin and then unlink
	_ = srv.o.Store.LinkAdminSSO("sub-123", "user1", "user1@urlxl.com")
	rec = postForm(t, h, "/settings/sso/unlink", url.Values{"csrf_token": {sess.CSRF}}, c)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want redirect", rec.Code)
	}

	ident, _ := srv.o.Store.AdminIdentity()
	if ident.SSOSub != "" || ident.SSOUsername != "" {
		t.Errorf("expected unlinked SSO, got: %+v", ident)
	}
}

func TestSettingsPageRendersWithLinkedSSO(t *testing.T) {
	h, srv := newWeb(t)
	setupAndLogin(t, h)
	c := loginCookie(t, h)

	// 1. Render when unlinked
	rec := get(t, h, "/settings", c)
	if rec.Code != http.StatusOK {
		t.Fatalf("settings page status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Link SSO Identity") {
		t.Errorf("expected 'Link SSO Identity' in unlinked settings HTML")
	}

	// 2. Link identity and render again
	_ = srv.o.Store.LinkAdminSSO("sso-sub-xyz", "yoshi_admin", "yoshi@urlxl.com")
	rec = get(t, h, "/settings", c)
	if rec.Code != http.StatusOK {
		t.Fatalf("settings page status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "SSO Identity Linked") || !strings.Contains(rec.Body.String(), "yoshi_admin") {
		t.Errorf("expected 'SSO Identity Linked' and 'yoshi_admin' in settings HTML, got: %s", rec.Body.String())
	}
}
