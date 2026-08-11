package web

import (
	"net/netip"
	"strings"
	"testing"

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
	srv.o.AllowTailscale = true

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
