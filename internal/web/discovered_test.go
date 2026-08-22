package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yoshiofthewire/kydns-server/internal/discovery/dhcp"
	"github.com/yoshiofthewire/kydns-server/internal/health"
)

func TestDiscoveredListsLeases(t *testing.T) {
	h, srv, c, _ := loggedIn(t)
	srv.o.Leases = func() []dhcp.Lease {
		return []dhcp.Lease{
			{Hostname: "laptop", IP: "192.168.1.50", MAC: "aa:bb:cc:dd:ee:01"},
			{Hostname: "printer", IP: "192.168.1.51", MAC: "aa:bb:cc:dd:ee:02"},
		}
	}
	srv.o.DiscoveryOn = func() bool { return true }
	body := page(t, h, "/discovered", c)
	for _, want := range []string{"laptop", "192.168.1.50", "printer", "aa:bb:cc:dd:ee:02"} {
		if !strings.Contains(body, want) {
			t.Errorf("discovered page missing %q", want)
		}
	}
}

// With discovery off the screen says so rather than showing an empty table.
func TestDiscoveredOffSaysSo(t *testing.T) {
	h, _, c, _ := loggedIn(t)
	body := page(t, h, "/discovered", c)
	if !strings.Contains(body, "dhcp_lease_file") {
		t.Errorf("discovered page does not explain how to enable discovery:\n%s", body)
	}
}

// DiscoveryOn, not a non-nil Leases, is what the page reports. Leases is
// wired unconditionally now, so a page that still read it for the on/off
// signal would claim discovery was enabled forever and render the explanatory
// empty state as an empty table.
func TestDiscoveredOnOffFollowsDiscoveryOn(t *testing.T) {
	h, srv, c, _ := loggedIn(t)
	on := false
	srv.o.Leases = func() []dhcp.Lease {
		return []dhcp.Lease{{Hostname: "laptop", IP: "192.168.1.50"}}
	}
	srv.o.DiscoveryOn = func() bool { return on }

	off := page(t, h, "/discovered", c)
	if !strings.Contains(off, "dhcp_lease_file") {
		t.Errorf("with discovery off the page does not explain how to enable it:\n%s", off)
	}
	if strings.Contains(off, "192.168.1.50") {
		t.Errorf("with discovery off the page still listed a lease:\n%s", off)
	}

	on = true
	live := page(t, h, "/discovered", c)
	if !strings.Contains(live, "192.168.1.50") {
		t.Errorf("with discovery on the lease is missing:\n%s", live)
	}
	if strings.Contains(live, "dhcp_lease_file") {
		t.Errorf("with discovery on the page still says discovery is off:\n%s", live)
	}
}

// A lease shadowed by a service must be marked, not silently listed as though
// it were resolving.
func TestShadowedLeaseIsMarked(t *testing.T) {
	h, srv, c, csrf := loggedIn(t)
	postForm(t, h, "/services/new", url.Values{
		"name": {"laptop"}, "address": {"192.168.1.99"}, "csrf_token": {csrf},
	}, c)
	srv.o.Leases = func() []dhcp.Lease {
		return []dhcp.Lease{{Hostname: "laptop", IP: "192.168.1.50"}}
	}
	srv.o.DiscoveryOn = func() bool { return true }
	body := page(t, h, "/discovered", c)
	if !strings.Contains(strings.ToLower(body), "shadowed") {
		t.Errorf("shadowed lease not marked:\n%s", body)
	}
}

// A manual record outranks a lease too, so it shadows just as a service does.
func TestLeaseShadowedByManualRecord(t *testing.T) {
	h, srv, c, csrf := loggedIn(t)
	postForm(t, h, "/records/new", url.Values{
		"name": {"printer.home.arpa."}, "type": {"A"}, "value": {"192.168.1.99"},
		"csrf_token": {csrf},
	}, c)
	srv.o.Leases = func() []dhcp.Lease {
		return []dhcp.Lease{{Hostname: "printer", IP: "192.168.1.51"}}
	}
	srv.o.DiscoveryOn = func() bool { return true }
	if !strings.Contains(strings.ToLower(page(t, h, "/discovered", c)), "shadowed") {
		t.Error("lease shadowed by a manual record was not marked")
	}
}

func TestPromoteLeaseCreatesService(t *testing.T) {
	h, srv, c, csrf := loggedIn(t)
	srv.o.Leases = func() []dhcp.Lease {
		return []dhcp.Lease{{Hostname: "laptop", IP: "192.168.1.50", MAC: "aa:bb:cc:dd:ee:01"}}
	}
	srv.o.DiscoveryOn = func() bool { return true }
	rec := postForm(t, h, "/discovered/promote", url.Values{
		"ip": {"192.168.1.50"}, "csrf_token": {csrf},
	}, c)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("promote = %d: %s", rec.Code, rec.Body)
	}
	svcs, err := srv.o.Registry.Services()
	if err != nil {
		t.Fatal(err)
	}
	if len(svcs) != 1 || svcs[0].Name != "laptop" {
		t.Fatalf("Services() = %+v, want a promoted laptop service", svcs)
	}
	if svcs[0].Addresses[0].Address != "192.168.1.50" {
		t.Errorf("promoted address = %q", svcs[0].Addresses[0].Address)
	}
	// The MAC travels with the address, so a promoted device keeps it once the
	// built-in DHCP server is the one handing addresses out.
	if svcs[0].MAC != "aa:bb:cc:dd:ee:01" {
		t.Errorf("promoted MAC = %q, want the lease's", svcs[0].MAC)
	}
}

func TestPromoteUnknownLeaseFails(t *testing.T) {
	h, srv, c, csrf := loggedIn(t)
	srv.o.Leases = func() []dhcp.Lease { return nil }
	srv.o.DiscoveryOn = func() bool { return true }
	rec := postForm(t, h, "/discovered/promote", url.Values{
		"ip": {"10.0.0.1"}, "csrf_token": {csrf},
	}, c)
	if rec.Code == http.StatusSeeOther {
		t.Error("promoting a lease that does not exist succeeded")
	}
}

func TestServicesShowHealthBadge(t *testing.T) {
	h, srv, c, csrf := loggedIn(t)
	postForm(t, h, "/services/new", url.Values{
		"name": {"kypost"}, "address": {"192.168.1.20"}, "csrf_token": {csrf},
	}, c)
	svcs, _ := srv.o.Registry.Services()
	srv.o.Health = func() []health.Status {
		return []health.Status{{ServiceID: svcs[0].ID, Name: "kypost", State: "down", Since: time.Now()}}
	}
	body := page(t, h, "/services", c)
	if !strings.Contains(body, "down") {
		t.Errorf("services page does not show the health state:\n%s", body)
	}
	if !strings.Contains(body, "data-health-for") {
		t.Error("health cell is missing the attribute live.js updates")
	}
}

// With no health data the column must not claim everything is fine.
func TestServicesHealthUnknownWithoutChecker(t *testing.T) {
	h, _, c, csrf := loggedIn(t)
	postForm(t, h, "/services/new", url.Values{
		"name": {"kypost"}, "address": {"192.168.1.20"}, "csrf_token": {csrf},
	}, c)
	body := page(t, h, "/services", c)
	if strings.Contains(body, ">up<") {
		t.Error("services page claims up with no health checker configured")
	}
	if !strings.Contains(body, "unknown") {
		t.Error("services page does not report unknown health")
	}
}

// A dnsmasq lease file that also holds DHCPv6 leases puts the IAID, not a MAC,
// in the MAC column. Promote names an address; an identifier it cannot reserve
// with must cost the name, not the promotion.
func TestPromoteKeepsTheNameWhenTheLeaseCarriesNoMAC(t *testing.T) {
	h, srv, c, csrf := loggedIn(t)
	srv.o.Leases = func() []dhcp.Lease {
		return []dhcp.Lease{{Hostname: "printer", IP: "192.168.1.51", MAC: "163461164"}}
	}
	srv.o.DiscoveryOn = func() bool { return true }
	rec := postForm(t, h, "/discovered/promote", url.Values{
		"ip": {"192.168.1.51"}, "csrf_token": {csrf},
	}, c)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("promote of a lease with a DHCPv6 IAID = %d: %s", rec.Code, rec.Body)
	}
	svcs, err := srv.o.Registry.Services()
	if err != nil {
		t.Fatal(err)
	}
	if len(svcs) != 1 || svcs[0].Name != "printer" {
		t.Fatalf("Services() = %+v, want the printer promoted", svcs)
	}
	if svcs[0].MAC != "" {
		t.Errorf("service MAC = %q, want none: %q is not a MAC", svcs[0].MAC, "163461164")
	}
}

// One device with two hostnames holds two leases on one MAC. The second
// promote gets a name without a reservation; only one service may claim a MAC.
func TestPromoteOfASecondLeaseOnOneMACKeepsTheName(t *testing.T) {
	h, srv, c, csrf := loggedIn(t)
	srv.o.Leases = func() []dhcp.Lease {
		return []dhcp.Lease{
			{Hostname: "nas", IP: "192.168.1.60", MAC: "aa:bb:cc:dd:ee:11"},
			{Hostname: "nas-mgmt", IP: "192.168.1.61", MAC: "aa:bb:cc:dd:ee:11"},
		}
	}
	srv.o.DiscoveryOn = func() bool { return true }
	for _, ip := range []string{"192.168.1.60", "192.168.1.61"} {
		rec := postForm(t, h, "/discovered/promote", url.Values{
			"ip": {ip}, "csrf_token": {csrf},
		}, c)
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("promote %s = %d: %s", ip, rec.Code, rec.Body)
		}
	}
	svcs, err := srv.o.Registry.Services()
	if err != nil {
		t.Fatal(err)
	}
	if len(svcs) != 2 {
		t.Fatalf("Services() = %+v, want both leases promoted", svcs)
	}
	macs := map[string]string{}
	for _, svc := range svcs {
		macs[svc.Name] = svc.MAC
	}
	if macs["nas"] != "aa:bb:cc:dd:ee:11" {
		t.Errorf("first promote MAC = %q, want the lease's", macs["nas"])
	}
	if macs["nas-mgmt"] != "" {
		t.Errorf("second promote MAC = %q, want none: the MAC is already reserved", macs["nas-mgmt"])
	}
}
