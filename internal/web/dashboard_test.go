package web

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/yoshiofthewire/kydns-server/internal/dnsserver"
	"github.com/yoshiofthewire/kydns-server/internal/store"
)

func TestDashboardShowsRefusalCounters(t *testing.T) {
	h, srv := newWeb(t)
	setupAndLogin(t, h)
	c := loginCookie(t, h)
	srv.o.ACL.Allow(netip.MustParseAddr("8.8.8.8"))
	srv.o.ACL.Allow(netip.MustParseAddr("100.64.0.1"))

	body := get(t, h, "/", c).Body.String()
	if !strings.Contains(body, "Refused queries") {
		t.Error("dashboard does not show refusal counters")
	}
	if !strings.Contains(body, `class="banner"`) {
		t.Errorf("dashboard did not render the banner after a CGNAT refusal:\n%s", body)
	}
	if !strings.Contains(body, "allow_tailscale") {
		t.Error("banner does not name the config key")
	}
}

func TestDashboardWithoutBanner(t *testing.T) {
	h, srv := newWeb(t)
	setupAndLogin(t, h)
	c := loginCookie(t, h)
	setAllowTailscale(t, srv, true)

	if strings.Contains(get(t, h, "/", c).Body.String(), `class="banner"`) {
		t.Error("banner rendered when there was nothing to report")
	}
}

// Condition 2 reaches the dashboard too, before any client has been refused.
func TestDashboardBannerForUnreachableView(t *testing.T) {
	h, srv := newWeb(t)
	setupAndLogin(t, h)
	c := loginCookie(t, h)
	if err := srv.o.Registry.PutView(store.View{
		Name: "tailnet", Subnets: []string{"100.64.0.0/10"},
	}); err != nil {
		t.Fatal(err)
	}
	body := get(t, h, "/", c).Body.String()
	if !strings.Contains(body, `class="banner"`) {
		t.Errorf("no banner for an unreachable view:\n%s", body)
	}
	if !strings.Contains(body, "tailnet") {
		t.Error("banner does not name the offending view")
	}
}

// Total DNS failure has to be loud on the first screen. Before this, an
// all-encrypted list with every entry timing out rendered identically to a
// healthy system.
func TestDashboardBannerWhenEveryUpstreamIsDown(t *testing.T) {
	h, srv := newWeb(t)
	setupAndLogin(t, h)
	c := loginCookie(t, h)
	setAllowTailscale(t, srv, true) // keep the Tailscale banner out of the picture
	srv.o.Upstreams = func() []dnsserver.UpstreamStatus {
		return []dnsserver.UpstreamStatus{
			{Spec: "tls://1.1.1.1:853", Secure: true, LastError: "dial tcp 1.1.1.1:853: i/o timeout"},
			{Spec: "tls://9.9.9.9:853", Secure: true, LastError: "dial tcp 9.9.9.9:853: i/o timeout"},
		}
	}
	body := get(t, h, "/", c).Body.String()
	if !strings.Contains(body, `class="banner"`) {
		t.Fatalf("no banner with every upstream down:\n%s", body)
	}
	if !strings.Contains(body, "i/o timeout") {
		t.Error("banner does not report why the upstreams failed")
	}
	if !strings.Contains(body, `class="badge warn"`) {
		t.Error("a failing encrypted upstream still renders as a healthy chip")
	}
}

// The same wiring with everything working stays quiet, chips included.
func TestDashboardQuietWhenUpstreamsAreHealthy(t *testing.T) {
	h, srv := newWeb(t)
	setupAndLogin(t, h)
	c := loginCookie(t, h)
	setAllowTailscale(t, srv, true)
	srv.o.Upstreams = func() []dnsserver.UpstreamStatus {
		return []dnsserver.UpstreamStatus{{Spec: "tls://1.1.1.1:853", Secure: true}}
	}
	body := get(t, h, "/", c).Body.String()
	if strings.Contains(body, `class="banner"`) {
		t.Errorf("banner rendered with a healthy encrypted upstream:\n%s", body)
	}
	if strings.Contains(body, `class="badge warn"`) {
		t.Error("healthy encrypted upstream chip is badged as a warning")
	}
}

// The complaint this answers: a working server showed only configuration
// counts, so success was invisible. The traffic numbers have to be on the page
// server-side, not only in the JSON the charts poll.
func TestDashboardShowsTrafficCounters(t *testing.T) {
	h, srv := newWeb(t)
	setupAndLogin(t, h)
	c := loginCookie(t, h)
	setAllowTailscale(t, srv, true)
	withMetrics(srv)

	body := get(t, h, "/", c).Body.String()
	for _, want := range []string{"Queries", "Cache hit rate", "Avg response", "Uptime"} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard is missing the %q stat", want)
		}
	}
	if !strings.Contains(body, `data-stat="total"`) {
		t.Error("no data-stat hook for the live refresh to update")
	}
	if !strings.Contains(body, ">3<") {
		t.Errorf("the query count was not rendered server-side:\n%s", body)
	}
}

func TestDashboardMountsTheCharts(t *testing.T) {
	h, srv := newWeb(t)
	setupAndLogin(t, h)
	c := loginCookie(t, h)
	setAllowTailscale(t, srv, true)
	withMetrics(srv)

	body := get(t, h, "/", c).Body.String()
	for _, id := range []string{"chart-queries", "chart-cache", "chart-latency"} {
		if !strings.Contains(body, id) {
			t.Errorf("dashboard has no mount point for %s", id)
		}
	}
	// With scripting off the charts cannot draw, and the page has to say so
	// rather than show three empty boxes.
	if !strings.Contains(body, "<noscript>") {
		t.Error("charts have no no-JavaScript fallback text")
	}
}

func TestDashboardListsTopBlockedNames(t *testing.T) {
	h, srv := newWeb(t)
	setupAndLogin(t, h)
	c := loginCookie(t, h)
	setAllowTailscale(t, srv, true)
	if _, err := srv.o.Policy.AddRule("deny", "ads.example.com"); err != nil {
		t.Fatal(err)
	}
	srv.o.Policy.Decide("ads.example.com.")

	body := get(t, h, "/", c).Body.String()
	if !strings.Contains(body, "ads.example.com") {
		t.Errorf("the blocked name is not on the dashboard:\n%s", body)
	}
}

func TestDashboardCountsEntities(t *testing.T) {
	h, srv := newWeb(t)
	setupAndLogin(t, h)
	c := loginCookie(t, h)
	if _, err := srv.o.Registry.PutService(store.Service{
		Name: "kypost", Addresses: []store.Address{{Address: "192.168.1.20"}},
	}); err != nil {
		t.Fatal(err)
	}
	body := get(t, h, "/", c).Body.String()
	if !strings.Contains(body, "Services") {
		t.Error("dashboard missing the services stat")
	}
}
