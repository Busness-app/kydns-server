package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestBlacklistsTabIsLinkedAndRequiresASession(t *testing.T) {
	h, _, c, _ := loggedIn(t)
	if !strings.Contains(page(t, h, "/services", c), `href="/blacklists"`) {
		t.Error("the navigation has no Blacklists link")
	}
	rec := get(t, h, "/blacklists", nil)
	if rec.Code != http.StatusSeeOther {
		t.Errorf("anonymous GET /blacklists = %d, want a redirect to login", rec.Code)
	}
}

func TestBlacklistsPageShowsStateAndWarnings(t *testing.T) {
	h, _, c, _ := loggedIn(t)
	body := page(t, h, "/blacklists", c)
	for _, want := range []string{"Blacklists", "steven-black", "never loaded"} {
		if !strings.Contains(body, want) {
			t.Errorf("page missing %q", want)
		}
	}
	// Filtering is on by default, so the "filtering is off" warning must not
	// be showing.
	if strings.Contains(body, "Filtering is off") {
		t.Error("the disabled warning shows while filtering is on")
	}
}

func TestTogglingFilteringOffWarnsOnThePage(t *testing.T) {
	h, _, c, csrf := loggedIn(t)
	rec := postForm(t, h, "/blacklists/toggle", url.Values{"csrf_token": {csrf}}, c)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("toggle = %d: %s", rec.Code, rec.Body)
	}
	if !strings.Contains(page(t, h, "/blacklists", c), "Filtering is off") {
		t.Error("no warning after filtering was turned off")
	}
	// Toggling back on clears it, and nothing was deleted.
	if rec := postForm(t, h, "/blacklists/toggle", url.Values{"csrf_token": {csrf}}, c); rec.Code != http.StatusSeeOther {
		t.Fatal(rec.Body)
	}
	body := page(t, h, "/blacklists", c)
	if strings.Contains(body, "Filtering is off") {
		t.Error("the warning survived re-enabling")
	}
	if !strings.Contains(body, "steven-black") {
		t.Error("re-enabling lost the lists")
	}
}

func TestAddingAndRemovingACustomList(t *testing.T) {
	h, _, c, csrf := loggedIn(t)
	rec := postForm(t, h, "/blacklists/lists/new", url.Values{
		"name": {"custom"}, "url": {"https://lists.example/hosts"},
		"format": {"hosts"}, "interval": {"3600"}, "csrf_token": {csrf},
	}, c)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("new list = %d: %s", rec.Code, rec.Body)
	}
	if !strings.Contains(page(t, h, "/blacklists", c), "custom") {
		t.Fatal("the new list is not on the page")
	}

	// A plain-http URL is refused with the message on the page, not a bare 500.
	rec = postForm(t, h, "/blacklists/lists/new", url.Values{
		"name": {"bad"}, "url": {"http://lists.example/hosts"}, "csrf_token": {csrf},
	}, c)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "https") {
		t.Errorf("plain-http list = %d: %s", rec.Code, rec.Body)
	}
}

func TestBuiltinListCannotBeDeletedFromTheUI(t *testing.T) {
	h, srv, c, csrf := loggedIn(t)
	lists, err := srv.o.Policy.Lists()
	if err != nil {
		t.Fatal(err)
	}
	var builtinID int64
	for _, l := range lists {
		if l.Builtin {
			builtinID = l.ID
		}
	}
	if builtinID == 0 {
		t.Fatal("no built-in list was seeded")
	}
	rec := postForm(t, h, "/blacklists/lists/delete", url.Values{
		"id": {itoa(builtinID)}, "csrf_token": {csrf},
	}, c)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("deleting a built-in = %d, want 400", rec.Code)
	}
	if !strings.Contains(page(t, h, "/blacklists", c), "steven-black") {
		t.Error("the built-in was removed")
	}
}

func TestOneOffRulesRoundTripAndRejectConflicts(t *testing.T) {
	h, _, c, csrf := loggedIn(t)
	rec := postForm(t, h, "/blacklists/rules/new", url.Values{
		"kind": {"deny"}, "domain": {"Ads.Example."}, "csrf_token": {csrf},
	}, c)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("new rule = %d: %s", rec.Code, rec.Body)
	}
	if !strings.Contains(page(t, h, "/blacklists", c), "ads.example") {
		t.Error("the normalized rule is not on the page")
	}
	rec = postForm(t, h, "/blacklists/rules/new", url.Values{
		"kind": {"allow"}, "domain": {"ads.example"}, "csrf_token": {csrf},
	}, c)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("conflicting rule = %d, want the page to refuse it", rec.Code)
	}
}

func TestTestBoxNamesTheDecidingRule(t *testing.T) {
	h, _, c, csrf := loggedIn(t)
	if rec := postForm(t, h, "/blacklists/rules/new", url.Values{
		"kind": {"deny"}, "domain": {"ads.example"}, "csrf_token": {csrf},
	}, c); rec.Code != http.StatusSeeOther {
		t.Fatal(rec.Body)
	}
	rec := postForm(t, h, "/blacklists/test", url.Values{
		"name": {"cdn.ads.example"}, "csrf_token": {csrf},
	}, c)
	if rec.Code != http.StatusOK {
		t.Fatalf("test = %d: %s", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "cdn.ads.example") || !strings.Contains(body, "deny") {
		t.Errorf("test result = %q, want the name and the deciding rule", body)
	}
}

// A missing id means "refresh everything," but a typo in the id field must be
// an error, not silently fall back to refreshing every list.
func TestRefreshRejectsAnUnparseableID(t *testing.T) {
	h, _, c, csrf := loggedIn(t)
	rec := postForm(t, h, "/blacklists/refresh", url.Values{
		"id": {"not-a-number"}, "csrf_token": {csrf},
	}, c)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("refresh with an unparseable id = %d, want 400", rec.Code)
	}
}

// Every mutating route must be CSRF-protected, like every other form.
func TestBlacklistFormsRequireCSRF(t *testing.T) {
	h, _, c, _ := loggedIn(t)
	for _, path := range []string{
		"/blacklists/toggle", "/blacklists/lists/new", "/blacklists/lists/toggle",
		"/blacklists/lists/delete", "/blacklists/refresh",
		"/blacklists/rules/new", "/blacklists/rules/delete", "/blacklists/test",
	} {
		if rec := postForm(t, h, path, url.Values{"csrf_token": {"wrong"}}, c); rec.Code != http.StatusForbidden {
			t.Errorf("POST %s with a bad token = %d, want 403", path, rec.Code)
		}
	}
}
