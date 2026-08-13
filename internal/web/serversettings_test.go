package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// validForm is a complete, accepted settings post. Tests change one field.
func validForm(csrf string) url.Values {
	return url.Values{
		"private_domain":     {"home.arpa"},
		"reverse_zones":      {"192.168.1.0/24"},
		"upstreams":          {"tls://1.1.1.1:853"},
		"allow_query":        {"192.168.0.0/16"},
		"ttl":                {"120"},
		"cache_min_ttl":      {"5"},
		"cache_max_ttl":      {"3600"},
		"negative_max_ttl":   {"300"},
		"cache_entries":      {"10000"},
		"discovery_interval": {"30"},
		"health_interval":    {"30"},
		"health_timeout":     {"5"},
		"health_workers":     {"8"},
		"csrf_token":         {csrf},
	}
}

func TestSettingsPageRendersTheForm(t *testing.T) {
	h, srv, c, _ := loggedIn(t)
	srv.o.Config = testConfig()
	body := page(t, h, "/settings", c)

	for _, want := range []string{
		`name="private_domain"`, `name="upstreams"`, `name="allow_query"`,
		`name="ttl"`, `name="cache_entries"`, `name="log_queries"`,
		`name="allow_tailscale"`, `name="health_workers"`,
		`action="/settings/server"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the form is missing %s", want)
		}
	}
	// The three keys the file still owns stay visible and read-only.
	if !strings.Contains(body, "admin.listen") || !strings.Contains(body, "data_dir") {
		t.Error("the file-owned keys are no longer shown")
	}
}

func TestPostServerSettingsSaves(t *testing.T) {
	h, srv, c, csrf := loggedIn(t)

	form := validForm(csrf)
	form.Set("log_queries", "on")
	rec := postForm(t, h, "/settings/server", form, c)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d, want a redirect: %s", rec.Code, rec.Body)
	}
	cur, _ := srv.o.Settings.Get()
	if cur.TTL != 120 {
		t.Errorf("ttl not saved: %d", cur.TTL)
	}
	if !cur.LogQueries {
		t.Error("the checkbox did not save")
	}
	// An unchecked checkbox posts nothing at all, which must mean off, not
	// unchanged: otherwise a toggle can be turned on but never off.
	if cur.LogClientIP {
		t.Error("an unchecked box was read as unchanged instead of off")
	}
	if !strings.Contains(page(t, h, "/settings", c), `value="120"`) {
		t.Error("the saved value is not shown back in the form")
	}
}

// A checkbox that is on must go off when the box is cleared.
func TestPostServerSettingsClearsCheckbox(t *testing.T) {
	h, srv, c, csrf := loggedIn(t)

	form := validForm(csrf)
	form.Set("allow_tailscale", "on")
	form.Set("log_queries", "on")
	form.Set("log_client_ip", "on")
	if rec := postForm(t, h, "/settings/server", form, c); rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if cur, _ := srv.o.Settings.Get(); !cur.AllowTailscale || !cur.LogClientIP {
		t.Fatalf("the boxes did not save: %+v", cur)
	}
	if rec := postForm(t, h, "/settings/server", validForm(csrf), c); rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	cur, _ := srv.o.Settings.Get()
	if cur.AllowTailscale || cur.LogQueries || cur.LogClientIP {
		t.Errorf("a cleared box stayed on: %+v", cur)
	}
}

// Turning on query logging must never start recording client IPs: the two
// opt-ins are independent, which LOGGING.md promises.
func TestQueryLoggingDoesNotEnableClientIP(t *testing.T) {
	h, srv, c, csrf := loggedIn(t)
	form := validForm(csrf)
	form.Set("log_queries", "on")
	// A rejected save would leave LogClientIP false for the wrong reason.
	if rec := postForm(t, h, "/settings/server", form, c); rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d, want a redirect: %s", rec.Code, rec.Body)
	}
	cur, _ := srv.o.Settings.Get()
	if cur.LogClientIP {
		t.Error("log_queries turned on client IP logging")
	}
}

// A rejected save must re-render with the field named and the operator's input
// still in the boxes, not discard what they typed.
func TestPostServerSettingsShowsFieldError(t *testing.T) {
	h, srv, c, csrf := loggedIn(t)
	before, _ := srv.o.Settings.Get()

	form := validForm(csrf)
	form.Set("allow_query", "0.0.0.0/0")
	form.Set("upstreams", "tls://1.1.1.1:853\ntls://9.9.9.9:853")
	rec := postForm(t, h, "/settings/server", form, c)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "allow_query") {
		t.Error("the error does not name the field")
	}
	if !strings.Contains(body, "0.0.0.0/0") {
		t.Error("the rejected input was discarded instead of shown back")
	}
	if !strings.Contains(body, "tls://9.9.9.9:853") {
		t.Error("an unrelated typed field was discarded")
	}
	after, _ := srv.o.Settings.Get()
	if len(after.AllowQuery) != len(before.AllowQuery) {
		t.Error("a rejected save still changed the stored ACL")
	}
}

// A non-numeric entry is reported against its own field, not silently zeroed.
func TestPostServerSettingsRejectsNonNumber(t *testing.T) {
	h, srv, c, csrf := loggedIn(t)
	form := validForm(csrf)
	form.Set("ttl", "sixty")
	rec := postForm(t, h, "/settings/server", form, c)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "ttl") {
		t.Error("the error does not name the field")
	}
	// The seeded value, unchanged: a rejected save must not write at all.
	if cur, _ := srv.o.Settings.Get(); cur.TTL != 60 {
		t.Errorf("a bad number reached the store: ttl = %d", cur.TTL)
	}
}

func TestPostServerSettingsAcceptsConfirmedPublicRange(t *testing.T) {
	h, _, c, csrf := loggedIn(t)
	form := validForm(csrf)
	form.Set("allow_query", "192.168.0.0/16\n0.0.0.0/0")
	form.Set("confirm_public", "0.0.0.0/0")

	if rec := postForm(t, h, "/settings/server", form, c); rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	// Once exposed, the dashboard must say so on every page load.
	if body := page(t, h, "/", c); !strings.Contains(body, "open resolver") {
		t.Error("no standing warning after a public range was allowed")
	}
	if body := page(t, h, "/settings", c); !strings.Contains(body, "open resolver") {
		t.Error("the settings page does not warn about the exposure")
	}
}

// The confirmation authorises exactly the prefix typed into it. Confirming
// something else must not let a different public range through.
func TestConfirmationMustMatchThePrefix(t *testing.T) {
	h, srv, c, csrf := loggedIn(t)
	form := validForm(csrf)
	form.Set("allow_query", "0.0.0.0/0")
	form.Set("confirm_public", "8.8.8.0/24")
	if rec := postForm(t, h, "/settings/server", form, c); rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", rec.Code)
	}
	if cur, _ := srv.o.Settings.Get(); len(cur.AllowQuery) != 1 || cur.AllowQuery[0] != "192.168.0.0/16" {
		t.Errorf("the ACL changed anyway: %v", cur.AllowQuery)
	}
}

// The warning shows the masked prefix: 192.168.1.99/0 matches everything while
// reading as a LAN address.
func TestExposureBannerShowsTheMaskedPrefix(t *testing.T) {
	h, _, c, csrf := loggedIn(t)
	form := validForm(csrf)
	form.Set("allow_query", "192.168.1.99/0")
	form.Set("confirm_public", "0.0.0.0/0")
	if rec := postForm(t, h, "/settings/server", form, c); rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	body := page(t, h, "/", c)
	if !strings.Contains(body, "0.0.0.0/0") {
		t.Error("the banner does not show what the prefix actually matches")
	}
	if strings.Contains(body, "192.168.1.99/0") {
		t.Error("the banner shows the unmasked prefix, which reads as a LAN address")
	}
}

func TestPostServerSettingsRequiresCSRF(t *testing.T) {
	h, _, c, csrf := loggedIn(t)
	form := validForm(csrf)
	form.Del("csrf_token")
	if rec := postForm(t, h, "/settings/server", form, c); rec.Code == http.StatusSeeOther {
		t.Fatal("a save without a CSRF token succeeded")
	}
}

func TestRestartPendingBanner(t *testing.T) {
	h, srv, c, _ := loggedIn(t)
	srv.o.RestartPending = func() []RestartItem {
		return []RestartItem{{
			Key: "dns.private_domain", Running: "home.arpa", Stored: "lab.example",
		}}
	}
	body := page(t, h, "/settings", c)
	// "Restart to apply" is the banner's own text: "restart" and "home.arpa"
	// appear on the page with no banner at all, from the form's labels.
	for _, want := range []string{"Restart to apply", "home.arpa", "lab.example"} {
		if !strings.Contains(body, want) {
			t.Errorf("the banner does not mention %q", want)
		}
	}
}

// The read-only table holds only the keys the config file still owns. The rest
// live in the database, where showing the file's copy would be a lie.
func TestConfigTableHoldsOnlyFileOwnedKeys(t *testing.T) {
	h, srv, c, _ := loggedIn(t)
	srv.o.Config = testConfig()
	body := page(t, h, "/settings", c)
	for _, want := range []string{"data_dir", "dns.listen", "admin.listen"} {
		if !strings.Contains(body, want) {
			t.Errorf("config table missing %q", want)
		}
	}
	for _, gone := range []string{
		"dns.ttl", "dns.upstreams", "dns.allow_query", "dns.allow_tailscale",
		"discovery.interval", "health.workers",
	} {
		if strings.Contains(body, gone) {
			t.Errorf("config table still shows %q, which the database owns", gone)
		}
	}
}
