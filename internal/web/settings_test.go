package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yoshiofthewire/kydns-server/internal/config"
	"github.com/yoshiofthewire/kydns-server/internal/dnsserver"
)

func TestViewCreateAndList(t *testing.T) {
	h, _, c, csrf := loggedIn(t)
	rec := postForm(t, h, "/settings/views/new", url.Values{
		"name": {"tailnet"}, "subnets": {"100.64.0.0/10"}, "csrf_token": {csrf},
	}, c)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("create view = %d: %s", rec.Code, rec.Body)
	}
	body := page(t, h, "/settings", c)
	if !strings.Contains(body, "tailnet") || !strings.Contains(body, "100.64.0.0/10") {
		t.Errorf("settings page missing the view:\n%s", body)
	}
}

// Condition 2 of the banner, rendered inline where the operator is standing.
func TestUnreachableViewFlaggedInline(t *testing.T) {
	h, srv, c, csrf := loggedIn(t)
	srv.o.AllowTailscale = false
	postForm(t, h, "/settings/views/new", url.Values{
		"name": {"tailnet"}, "subnets": {"100.64.0.0/10"}, "csrf_token": {csrf},
	}, c)
	body := page(t, h, "/settings", c)
	if !strings.Contains(strings.ToLower(body), "unreachable") {
		t.Errorf("CGNAT view not flagged as unreachable:\n%s", body)
	}
	if !strings.Contains(body, "allow_tailscale") {
		t.Error("inline flag does not name the config key")
	}
}

func TestReachableViewNotFlagged(t *testing.T) {
	h, srv, c, csrf := loggedIn(t)
	srv.o.AllowTailscale = true
	postForm(t, h, "/settings/views/new", url.Values{
		"name": {"tailnet"}, "subnets": {"100.64.0.0/10"}, "csrf_token": {csrf},
	}, c)
	if strings.Contains(strings.ToLower(page(t, h, "/settings", c)), "unreachable") {
		t.Error("view flagged unreachable while allow_tailscale is on")
	}
}

func TestViewShowsReferenceCount(t *testing.T) {
	h, srv, c, csrf := loggedIn(t)
	addView(t, srv, "tailnet", "100.64.0.0/10")
	postForm(t, h, "/services/new", url.Values{
		"name": {"kypost"}, "address": {"100.101.102.103"}, "view": {"tailnet"},
		"csrf_token": {csrf},
	}, c)
	views, err := srv.o.Registry.Views()
	if err != nil || len(views) != 1 {
		t.Fatalf("Views() = %v, %v", views, err)
	}
	if !strings.Contains(page(t, h, "/settings", c), "Used by") {
		t.Error("settings page does not show a reference count column")
	}
}

func TestDeleteViewInUseShowsError(t *testing.T) {
	h, _, c, csrf := loggedIn(t)
	postForm(t, h, "/settings/views/new", url.Values{
		"name": {"tailnet"}, "subnets": {"100.64.0.0/10"}, "csrf_token": {csrf},
	}, c)
	postForm(t, h, "/services/new", url.Values{
		"name": {"kypost"}, "address": {"100.101.102.103"}, "view": {"tailnet"},
		"csrf_token": {csrf},
	}, c)
	rec := postForm(t, h, "/settings/views/delete", url.Values{
		"name": {"tailnet"}, "csrf_token": {csrf},
	}, c)
	if rec.Code == http.StatusSeeOther {
		t.Fatal("deleting an in-use view succeeded")
	}
	if !strings.Contains(strings.ToLower(rec.Body.String()), "referenced") {
		t.Errorf("error does not explain the view is in use:\n%s", rec.Body)
	}
}

func TestDeleteUnusedView(t *testing.T) {
	h, _, c, csrf := loggedIn(t)
	postForm(t, h, "/settings/views/new", url.Values{
		"name": {"spare"}, "subnets": {"10.9.0.0/16"}, "csrf_token": {csrf},
	}, c)
	if rec := postForm(t, h, "/settings/views/delete", url.Values{
		"name": {"spare"}, "csrf_token": {csrf},
	}, c); rec.Code != http.StatusSeeOther {
		t.Fatalf("delete = %d: %s", rec.Code, rec.Body)
	}
	if strings.Contains(page(t, h, "/settings", c), "spare") {
		t.Error("deleted view still listed")
	}
}

// A new token's plaintext is shown exactly once, then never again.
func TestTokenShownOnceThenNever(t *testing.T) {
	h, _, c, csrf := loggedIn(t)
	rec := postForm(t, h, "/settings/tokens/new", url.Values{
		"label": {"laptop"}, "csrf_token": {csrf},
	}, c)
	if rec.Code != http.StatusOK {
		t.Fatalf("create token = %d: %s", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	idx := strings.Index(body, "kydns_")
	if idx < 0 {
		t.Fatal("plaintext token not shown on creation")
	}
	plaintext := body[idx : idx+70]
	later := page(t, h, "/settings", c)
	if strings.Contains(later, plaintext) {
		t.Error("token plaintext still visible on a later page load")
	}
	if !strings.Contains(later, "laptop") {
		t.Error("token label missing from the list")
	}
}

func TestTokenRevoke(t *testing.T) {
	h, srv, c, csrf := loggedIn(t)
	postForm(t, h, "/settings/tokens/new", url.Values{"label": {"gone"}, "csrf_token": {csrf}}, c)
	toks, err := srv.o.Registry.Tokens()
	if err != nil || len(toks) != 1 {
		t.Fatalf("Tokens() = %v, %v", toks, err)
	}
	if rec := postForm(t, h, "/settings/tokens/delete", url.Values{
		"id": {itoa(toks[0].ID)}, "csrf_token": {csrf},
	}, c); rec.Code != http.StatusSeeOther {
		t.Fatalf("revoke = %d: %s", rec.Code, rec.Body)
	}
	if toks, _ = srv.o.Registry.Tokens(); len(toks) != 0 {
		t.Errorf("Tokens() = %+v after revoke, want empty", toks)
	}
}

func TestExportDownloads(t *testing.T) {
	h, _, c, csrf := loggedIn(t)
	postForm(t, h, "/services/new", url.Values{
		"name": {"kypost"}, "address": {"192.168.1.20"}, "csrf_token": {csrf},
	}, c)
	body := page(t, h, "/settings/export?format=yaml", c)
	if !strings.Contains(body, "kypost") {
		t.Errorf("export missing the service:\n%s", body)
	}
	for _, forbidden := range []string{"password_hash", "argon2", "kydns_"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("export leaked %q", forbidden)
		}
	}
}

func TestCacheFlushButton(t *testing.T) {
	h, srv, c, csrf := loggedIn(t)
	if rec := postForm(t, h, "/settings/cache/flush", url.Values{"csrf_token": {csrf}}, c); rec.Code != http.StatusSeeOther {
		t.Fatalf("flush = %d: %s", rec.Code, rec.Body)
	}
	if srv.o.Cache.Len() != 0 {
		t.Error("cache not flushed")
	}
}

func TestSettingsShowsReadOnlyConfig(t *testing.T) {
	h, srv, c, _ := loggedIn(t)
	srv.o.Config = &config.Config{
		DataDir: "/var/lib/kydns",
		DNS: config.DNSConfig{
			Listen: ":53", PrivateDomain: "home.arpa",
			Upstreams: []string{"1.1.1.1:53"}, AllowQuery: []string{"192.168.0.0/16"},
			TTL: 60, CacheEntries: 10000,
		},
		Admin: config.AdminConfig{Listen: "127.0.0.1:8053"},
	}
	body := page(t, h, "/settings", c)
	for _, want := range []string{
		"dns.upstreams", "1.1.1.1:53", "dns.private_domain", "home.arpa",
		"admin.listen", "data_dir", "/var/lib/kydns",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("config view missing %q", want)
		}
	}
	if !strings.Contains(strings.ToLower(body), "restarting kydns") {
		t.Error("config view does not say a restart is required")
	}
}

// allow_tailscale must read as on/off, not Go's true/false, and must be
// visible so the operator can see why tailnet clients are refused.
func TestConfigViewShowsAllowTailscale(t *testing.T) {
	h, srv, c, _ := loggedIn(t)
	srv.o.Config = &config.Config{DataDir: "/tmp", DNS: config.DNSConfig{AllowTailscale: false}}
	body := page(t, h, "/settings", c)
	if !strings.Contains(body, "dns.allow_tailscale") {
		t.Fatal("config view omits allow_tailscale")
	}
	if strings.Contains(body, ">false<") {
		t.Error("allow_tailscale rendered as Go's false, want off")
	}
}

// The section is omitted rather than rendering an empty table when no config
// is wired in.
func TestConfigViewAbsentWithoutConfig(t *testing.T) {
	h, srv, c, _ := loggedIn(t)
	srv.o.Config = nil
	if strings.Contains(page(t, h, "/settings", c), "dns.upstreams") {
		t.Error("config section rendered with no config loaded")
	}
}

// Config carries no secrets today; this guards against one being added to the
// display later without thought.
func TestConfigViewCarriesNoSecrets(t *testing.T) {
	h, srv, c, csrf := loggedIn(t)
	srv.o.Config = &config.Config{DataDir: "/tmp", DNS: config.DNSConfig{Listen: ":53"}}
	postForm(t, h, "/settings/tokens/new", url.Values{"label": {"x"}, "csrf_token": {csrf}}, c)
	body := page(t, h, "/settings", c)
	for _, forbidden := range []string{"password_hash", "argon2", "kydns_"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("settings page leaked %q", forbidden)
		}
	}
}

// Strict mode is only survivable if the operator can see why it is failing.
func TestSettingsShowsUpstreamStatus(t *testing.T) {
	h, srv, c, _ := loggedIn(t)
	srv.o.Upstreams = func() []dnsserver.UpstreamStatus {
		return []dnsserver.UpstreamStatus{
			{
				Spec: "tls://1.1.1.1:853", Secure: true,
				LastError: "dial tcp 1.1.1.1:853: i/o timeout",
				LastErrAt: time.Date(2026, 8, 14, 9, 30, 0, 0, time.UTC),
			},
			{Spec: "udp://192.168.1.1:53"},
		}
	}
	body := page(t, h, "/settings", c)
	for _, want := range []string{
		"tls://1.1.1.1:853",
		"i/o timeout",
		// A three-second-old timeout and a three-day-old one read alike
		// without this.
		"2026-08-14 09:30:00 UTC",
		"udp://192.168.1.1:53",
		"plaintext",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("settings page does not contain %q", want)
		}
	}
}

// With no forwarder wired the card is absent rather than an empty table.
func TestSettingsOmitsUpstreamsWhenUnset(t *testing.T) {
	h, _, c, _ := loggedIn(t)
	if strings.Contains(page(t, h, "/settings", c), "<h3>Upstreams</h3>") {
		t.Error("settings renders an upstream card with no forwarder wired")
	}
}

// The Discovered nav link exists; it must not 404 before plan 3.
func TestDiscoveredPlaceholder(t *testing.T) {
	h, _, c, _ := loggedIn(t)
	if !strings.Contains(page(t, h, "/discovered", c), "DHCP") {
		t.Error("discovered placeholder does not explain what will appear here")
	}
}
