package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/yoshiofthewire/kydns-server/internal/store"
)

// loggedIn returns a handler, server, session cookie, and CSRF token.
func loggedIn(t *testing.T) (http.Handler, *Server, *http.Cookie, string) {
	t.Helper()
	h, srv := newWeb(t)
	setupAndLogin(t, h)
	c := loginCookie(t, h)
	sess, ok := srv.o.Sessions.Get(c.Value)
	if !ok {
		t.Fatal("no session")
	}
	return h, srv, c, sess.CSRF
}

// addView creates a view through the registry. The settings screen that
// exposes this over HTTP arrives in a later task; these tests exercise the
// services screen in isolation.
func addView(t *testing.T, srv *Server, name string, subnets ...string) {
	t.Helper()
	if err := srv.o.Registry.PutView(store.View{Name: name, Subnets: subnets}); err != nil {
		t.Fatal(err)
	}
}

func page(t *testing.T, h http.Handler, path string, c *http.Cookie) string {
	t.Helper()
	rec := get(t, h, path, c)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d: %s", path, rec.Code, rec.Body)
	}
	return rec.Body.String()
}

func TestServiceCreateAppearsInTable(t *testing.T) {
	h, _, c, csrf := loggedIn(t)
	rec := postForm(t, h, "/services/new", url.Values{
		"name": {"kypost"}, "address": {"192.168.1.20"}, "view": {""},
		"aliases": {"webmail"}, "csrf_token": {csrf},
	}, c)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("create = %d: %s", rec.Code, rec.Body)
	}
	body := page(t, h, "/services", c)
	for _, want := range []string{"kypost", "192.168.1.20", "webmail"} {
		if !strings.Contains(body, want) {
			t.Errorf("services page missing %q", want)
		}
	}
}

// Untagged addresses must read as "all views", never as a blank cell.
func TestUntaggedAddressLabelledAllViews(t *testing.T) {
	h, _, c, csrf := loggedIn(t)
	postForm(t, h, "/services/new", url.Values{
		"name": {"nas"}, "address": {"192.168.1.30"}, "csrf_token": {csrf},
	}, c)
	if !strings.Contains(page(t, h, "/services", c), "all views") {
		t.Error(`untagged address is not labelled "all views"`)
	}
}

func TestServiceCreateWithViewTag(t *testing.T) {
	h, srv, c, csrf := loggedIn(t)
	addView(t, srv, "tailnet", "100.64.0.0/10")
	rec := postForm(t, h, "/services/new", url.Values{
		"name": {"kypost"}, "address": {"100.101.102.103"}, "view": {"tailnet"},
		"csrf_token": {csrf},
	}, c)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("create = %d: %s", rec.Code, rec.Body)
	}
	if !strings.Contains(page(t, h, "/services", c), "tailnet") {
		t.Error("view tag not shown on the services page")
	}
}

// The Tailscale workflow in the UI: one name, a second view-tagged address.
func TestAddAddressToExistingService(t *testing.T) {
	h, srv, c, csrf := loggedIn(t)
	addView(t, srv, "tailnet", "100.64.0.0/10")
	postForm(t, h, "/services/new", url.Values{
		"name": {"kypost"}, "address": {"192.168.1.20"}, "csrf_token": {csrf},
	}, c)
	svcs, _ := srv.o.Registry.Services()
	if len(svcs) != 1 {
		t.Fatalf("Services() = %+v", svcs)
	}
	rec := postForm(t, h, "/services/address", url.Values{
		"id": {itoa(svcs[0].ID)}, "address": {"100.101.102.103"}, "view": {"tailnet"},
		"csrf_token": {csrf},
	}, c)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("add address = %d: %s", rec.Code, rec.Body)
	}
	body := page(t, h, "/services", c)
	if !strings.Contains(body, "100.101.102.103") || !strings.Contains(body, "192.168.1.20") {
		t.Errorf("both addresses should be listed:\n%s", body)
	}
	svcs, _ = srv.o.Registry.Services()
	if len(svcs) != 1 || len(svcs[0].Addresses) != 2 {
		t.Errorf("want one service with two addresses, got %+v", svcs)
	}
}

// A validation failure re-renders the form with the message, not a 500.
func TestServiceValidationErrorRendersInline(t *testing.T) {
	h, _, c, csrf := loggedIn(t)
	rec := postForm(t, h, "/services/new", url.Values{
		"name": {"bad_name"}, "address": {"192.168.1.20"}, "csrf_token": {csrf},
	}, c)
	if rec.Code == http.StatusSeeOther {
		t.Fatal("invalid service was accepted")
	}
	if rec.Code >= 500 {
		t.Fatalf("validation failure returned %d, want a re-rendered form", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "name") {
		t.Errorf("error page does not name the offending field:\n%s", rec.Body)
	}
}

func TestServiceDelete(t *testing.T) {
	h, srv, c, csrf := loggedIn(t)
	postForm(t, h, "/services/new", url.Values{
		"name": {"gone"}, "address": {"192.168.1.40"}, "csrf_token": {csrf},
	}, c)
	svcs, err := srv.o.Registry.Services()
	if err != nil || len(svcs) != 1 {
		t.Fatalf("Services() = %v, %v", svcs, err)
	}
	rec := postForm(t, h, "/services/delete", url.Values{
		"id": {itoa(svcs[0].ID)}, "csrf_token": {csrf},
	}, c)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("delete = %d: %s", rec.Code, rec.Body)
	}
	if strings.Contains(page(t, h, "/services", c), "gone") {
		t.Error("deleted service still on the page")
	}
}

// The view dropdown must offer every configured view plus the untagged option.
func TestServiceFormListsViews(t *testing.T) {
	h, srv, c, _ := loggedIn(t)
	addView(t, srv, "tailnet", "100.64.0.0/10")
	body := page(t, h, "/services", c)
	if !strings.Contains(body, `value="tailnet"`) {
		t.Error("view dropdown does not offer tailnet")
	}
	if !strings.Contains(body, "All views") {
		t.Error("view dropdown does not offer the untagged option")
	}
}

// The routing form is how an operator turns routing off without losing the
// proxy address, to tell whether a problem is the app or the proxy.
func TestServiceRoutingToggleOffKeepsProxyAddress(t *testing.T) {
	h, srv, c, csrf := loggedIn(t)
	postForm(t, h, "/services/new", url.Values{
		"name": {"kypost"}, "address": {"192.168.1.30"},
		"proxy_address": {"192.168.1.20"}, "route_via_proxy": {"on"},
		"csrf_token": {csrf},
	}, c)
	svcs, _ := srv.o.Registry.Services()
	if len(svcs) != 1 {
		t.Fatalf("Services() = %+v", svcs)
	}

	rec := postForm(t, h, "/services/routing", url.Values{
		"id": {itoa(svcs[0].ID)}, "proxy_address": {"192.168.1.20"},
		"csrf_token": {csrf},
	}, c)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("routing toggle off = %d: %s", rec.Code, rec.Body)
	}

	svcs, _ = srv.o.Registry.Services()
	if svcs[0].RouteViaProxy {
		t.Error("route_via_proxy still on after toggling off")
	}
	if svcs[0].ProxyAddress != "192.168.1.20" {
		t.Errorf("proxy_address = %q, want it kept", svcs[0].ProxyAddress)
	}
}

func TestServiceRoutingToggleOnWithAddress(t *testing.T) {
	h, srv, c, csrf := loggedIn(t)
	postForm(t, h, "/services/new", url.Values{
		"name": {"kypost"}, "address": {"192.168.1.30"},
		"proxy_address": {"192.168.1.20"}, "csrf_token": {csrf},
	}, c)
	svcs, _ := srv.o.Registry.Services()

	rec := postForm(t, h, "/services/routing", url.Values{
		"id": {itoa(svcs[0].ID)}, "proxy_address": {"192.168.1.20"},
		"route_via_proxy": {"on"}, "csrf_token": {csrf},
	}, c)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("routing toggle on = %d: %s", rec.Code, rec.Body)
	}

	svcs, _ = srv.o.Registry.Services()
	if !svcs[0].RouteViaProxy {
		t.Error("route_via_proxy still off after toggling on")
	}
}

func TestServiceRoutingChangesAddress(t *testing.T) {
	h, srv, c, csrf := loggedIn(t)
	postForm(t, h, "/services/new", url.Values{
		"name": {"kypost"}, "address": {"192.168.1.30"},
		"proxy_address": {"192.168.1.20"}, "route_via_proxy": {"on"},
		"csrf_token": {csrf},
	}, c)
	svcs, _ := srv.o.Registry.Services()

	rec := postForm(t, h, "/services/routing", url.Values{
		"id": {itoa(svcs[0].ID)}, "proxy_address": {"192.168.1.99"},
		"route_via_proxy": {"on"}, "csrf_token": {csrf},
	}, c)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("routing change = %d: %s", rec.Code, rec.Body)
	}

	svcs, _ = srv.o.Registry.Services()
	if svcs[0].ProxyAddress != "192.168.1.99" {
		t.Errorf("proxy_address = %q, want 192.168.1.99", svcs[0].ProxyAddress)
	}
}

// Validation lives in the registry; the form must surface it, not bypass it.
func TestServiceRoutingRejectsEmptyProxyAddress(t *testing.T) {
	h, srv, c, csrf := loggedIn(t)
	postForm(t, h, "/services/new", url.Values{
		"name": {"kypost"}, "address": {"192.168.1.30"},
		"proxy_address": {"192.168.1.20"}, "route_via_proxy": {"on"}, "csrf_token": {csrf},
	}, c)
	svcs, _ := srv.o.Registry.Services()

	rec := postForm(t, h, "/services/routing", url.Values{
		"id": {itoa(svcs[0].ID)}, "proxy_address": {""},
		"route_via_proxy": {"on"}, "csrf_token": {csrf},
	}, c)
	if rec.Code == http.StatusSeeOther {
		t.Fatal("routing on with an empty proxy address was accepted")
	}
	if rec.Code >= 500 {
		t.Fatalf("validation failure returned %d, want a re-rendered form", rec.Code)
	}

	svcs, _ = srv.o.Registry.Services()
	if !svcs[0].RouteViaProxy || svcs[0].ProxyAddress != "192.168.1.20" {
		t.Errorf("= %+v, want the rejected change left alone", svcs[0])
	}
}

func TestServiceFormAcceptsProxyFields(t *testing.T) {
	h, srv, c, csrf := loggedIn(t)

	postForm(t, h, "/services/new", url.Values{
		"name":            {"kypost"},
		"address":         {"192.168.1.30"},
		"proxy_address":   {"192.168.1.20"},
		"route_via_proxy": {"on"},
		"check_insecure":  {"on"},
		"csrf_token":      {csrf},
	}, c)

	svcs, err := srv.o.Registry.Services()
	if err != nil {
		t.Fatal(err)
	}
	if len(svcs) != 1 {
		t.Fatalf("services = %d, want 1", len(svcs))
	}
	if svcs[0].ProxyAddress != "192.168.1.20" || !svcs[0].RouteViaProxy {
		t.Errorf("= %+v, want the proxy fields set", svcs[0])
	}
	if !svcs[0].CheckInsecure {
		t.Error("check_insecure was not applied; it had no control before this change")
	}

	// The indirection has to be visible on the list, not buried in an edit.
	body := page(t, h, "/services", c)
	if !strings.Contains(body, "192.168.1.20") {
		t.Error("services table does not show the proxy address on a routed row")
	}
}
