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
	if !strings.Contains(strings.ToLower(page(t, h, "/discovered", c)), "shadowed") {
		t.Error("lease shadowed by a manual record was not marked")
	}
}

func TestPromoteLeaseCreatesService(t *testing.T) {
	h, srv, c, csrf := loggedIn(t)
	srv.o.Leases = func() []dhcp.Lease {
		return []dhcp.Lease{{Hostname: "laptop", IP: "192.168.1.50"}}
	}
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
}

func TestPromoteUnknownLeaseFails(t *testing.T) {
	h, srv, c, csrf := loggedIn(t)
	srv.o.Leases = func() []dhcp.Lease { return nil }
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
