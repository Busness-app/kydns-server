package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/yoshiofthewire/kydns-server/internal/settings"
	"github.com/yoshiofthewire/kydns-server/internal/store"
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

// addRecord writes a manual record straight through the registry, so a rename
// test starts from records that really are in the store.
func addRecord(t *testing.T, srv *Server, name, rtype, value string) {
	t.Helper()
	if _, err := srv.o.Registry.PutRecord(store.Record{Name: name, Type: rtype, Value: value}); err != nil {
		t.Fatal(err)
	}
}

// Renaming the private zone rewrites the operator's records. They see what
// will change and confirm it before anything is written.
func TestZoneRenameAsksBeforeMovingRecords(t *testing.T) {
	h, srv, c, csrf := loggedIn(t)
	addRecord(t, srv, "printer.home.arpa.", "A", "10.0.0.5")
	addRecord(t, srv, "www.home.arpa.", "CNAME", "nas.home.arpa.")

	form := validForm(csrf)
	form.Set("private_domain", "lan.example")
	rec := postForm(t, h, "/settings/server", form, c)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want the confirmation page: %s", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"printer.home.arpa.", "printer.lan.example.",
		"nas.lan.example.", // the CNAME target moves too, and is shown
		`name="confirm_rename"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the confirmation does not show %q", want)
		}
	}

	// Nothing may have been written yet.
	cur, _ := srv.o.Settings.Get()
	if cur.PrivateDomain != "home.arpa" {
		t.Errorf("private_domain = %q; the domain changed before it was confirmed", cur.PrivateDomain)
	}
	recs, err := srv.o.Registry.Records()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range recs {
		if strings.Contains(r.Name, "lan.example") {
			t.Errorf("record %q was moved before the rename was confirmed", r.Name)
		}
	}
}

// Confirming applies the rename: the domain, the record names, and the CNAME
// targets all land together.
func TestZoneRenameMovesRecordsOnceConfirmed(t *testing.T) {
	h, srv, c, csrf := loggedIn(t)
	addRecord(t, srv, "printer.home.arpa.", "A", "10.0.0.5")
	addRecord(t, srv, "www.home.arpa.", "CNAME", "nas.home.arpa.")

	form := validForm(csrf)
	form.Set("private_domain", "lan.example")
	form.Set("confirm_rename", "lan.example")
	if rec := postForm(t, h, "/settings/server", form, c); rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d, want a redirect: %s", rec.Code, rec.Body)
	}

	cur, _ := srv.o.Settings.Get()
	if cur.PrivateDomain != "lan.example" {
		t.Errorf("private_domain = %q, want lan.example", cur.PrivateDomain)
	}
	got := map[string]string{}
	recs, err := srv.o.Registry.Records()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range recs {
		got[r.Name] = r.Value
	}
	if v, ok := got["printer.lan.example."]; !ok || v != "10.0.0.5" {
		t.Errorf("records = %v, want printer moved into the new zone", got)
	}
	if v, ok := got["www.lan.example."]; !ok || v != "nas.lan.example." {
		t.Errorf("records = %v, want the CNAME and its target moved", got)
	}
}

// A confirmation for one domain must not authorize a different one.
func TestZoneRenameConfirmationIsForOneDomain(t *testing.T) {
	h, srv, c, csrf := loggedIn(t)
	addRecord(t, srv, "printer.home.arpa.", "A", "10.0.0.5")

	form := validForm(csrf)
	form.Set("private_domain", "other.example")
	form.Set("confirm_rename", "lan.example") // stale: confirms the previous try
	if rec := postForm(t, h, "/settings/server", form, c); rec.Code != http.StatusOK {
		t.Fatalf("status %d, want the confirmation page again", rec.Code)
	}
	cur, _ := srv.o.Settings.Get()
	if cur.PrivateDomain != "home.arpa" {
		t.Errorf("private_domain = %q; a stale confirmation authorized a different rename", cur.PrivateDomain)
	}
}

// With no records to move, a rename destroys nothing, so it does not stop to
// ask. Friction with nothing behind it teaches operators to click through.
func TestZoneRenameWithNoRecordsSavesStraightAway(t *testing.T) {
	h, srv, c, csrf := loggedIn(t)

	form := validForm(csrf)
	form.Set("private_domain", "lan.example")
	if rec := postForm(t, h, "/settings/server", form, c); rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d, want a redirect: %s", rec.Code, rec.Body)
	}
	cur, _ := srv.o.Settings.Get()
	if cur.PrivateDomain != "lan.example" {
		t.Errorf("private_domain = %q, want lan.example", cur.PrivateDomain)
	}
}

// Re-saving the same domain written differently is not a rename.
func TestZoneRenameIgnoresCaseAndTrailingDot(t *testing.T) {
	h, srv, c, csrf := loggedIn(t)
	addRecord(t, srv, "printer.home.arpa.", "A", "10.0.0.5")

	form := validForm(csrf)
	form.Set("private_domain", "HOME.ARPA.")
	if rec := postForm(t, h, "/settings/server", form, c); rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d, want a straight save: %s", rec.Code, rec.Body)
	}
}

// The settings form rebuilds the whole document from what was posted, and it
// has no DHCP fields yet. Anything it does not carry comes back zeroed, which
// for the built-in server means an unrelated save switches DHCP off on a LAN
// that is relying on it.
func TestPostServerSettingsKeepsTheDHCPConfiguration(t *testing.T) {
	h, srv, c, csrf := loggedIn(t)

	cur, err := srv.o.Settings.Get()
	if err != nil {
		t.Fatal(err)
	}
	cur.DHCPEnabled, cur.DHCPInterface = true, "eth0"
	cur.DHCPRangeStart, cur.DHCPRangeEnd = "192.168.1.100", "192.168.1.200"
	cur.DHCPGateway, cur.DHCPLeaseSeconds = "192.168.1.1", 3600
	cur.DHCPSecondaryDNS = "9.9.9.9"
	if err := srv.o.Settings.Set(cur, ""); err != nil {
		t.Fatal(err)
	}

	if rec := postForm(t, h, "/settings/server", validForm(csrf), c); rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	got, _ := srv.o.Settings.Get()
	if !got.DHCPEnabled || got.DHCPInterface != "eth0" ||
		got.DHCPRangeStart != "192.168.1.100" || got.DHCPRangeEnd != "192.168.1.200" ||
		got.DHCPGateway != "192.168.1.1" || got.DHCPLeaseSeconds != 3600 ||
		got.DHCPSecondaryDNS != "9.9.9.9" {
		t.Fatalf("an unrelated settings save wiped the DHCP configuration: %+v", got)
	}
}

// This handler rebuilds the whole settings row from what was posted, and the
// DHCP fields have no boxes on the form: they are carried over from the
// current values. If those cannot be read there is nothing to carry, so the
// save must be refused rather than written with seven zeroes — which would
// switch a running DHCP server off.
func TestPostServerSettingsRefusesWhenTheCurrentValuesCannotBeRead(t *testing.T) {
	h, srv, c, csrf := loggedIn(t)
	// Wired but never loaded, which is what liveSettings reports as not ok.
	st := srv.o.Store
	srv.o.Settings = settings.NewService(st, settings.NewHolder(func() (store.Settings, error) {
		v, _, err := st.Settings()
		return v, err
	}), nil)

	rec := postForm(t, h, "/settings/server", validForm(csrf), c)
	if rec.Code == http.StatusSeeOther {
		t.Fatal("the save was applied without the values it had to carry over")
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400 with a reason on the form", rec.Code)
	}
}
