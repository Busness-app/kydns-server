package web

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Busness-app/kydns-server/internal/adminapi"
	"github.com/Busness-app/kydns-server/internal/dhcpd"
	"github.com/Busness-app/kydns-server/internal/discovery/dhcp"
)

// errNoBind stands in for the listener refusing to start.
var errNoBind = errors.New("bind: permission denied")

// fakeDHCP is a runner whose state the test dictates. It opens no socket: the
// page reads it through the same API accessor production does.
type fakeDHCP struct {
	running  bool
	err      error
	foreign  []dhcpd.Foreign
	problems []dhcpd.ReservationProblem
}

func (f fakeDHCP) Status() (bool, error)                { return f.running, f.err }
func (f fakeDHCP) Foreign() []dhcpd.Foreign             { return f.foreign }
func (f fakeDHCP) Problems() []dhcpd.ReservationProblem { return f.problems }

// withDHCP attaches the runner to the API the page reads.
func withDHCP(run adminapi.DHCPRunner) func(*Options) {
	return func(o *Options) { o.API = o.API.WithDHCP(run) }
}

// setDHCPInterface writes the chosen interface through the one write path.
func setDHCPInterface(t *testing.T, srv *Server, name string) {
	t.Helper()
	v, err := srv.o.Settings.Get()
	if err != nil {
		t.Fatal(err)
	}
	v.DHCPInterface = name
	if err := srv.o.Settings.Set(v, ""); err != nil {
		t.Fatal(err)
	}
}

// renderDHCPState draws the tab from a given status. It covers the states the
// test host cannot be put into — a dual-stack segment, an interface that
// qualifies but is too small to cut a range out of.
func renderDHCPState(t *testing.T, srv *Server, st adminapi.DHCPStatus, errMsg string) string {
	t.Helper()
	rec := httptest.NewRecorder()
	srv.render(rec, httptest.NewRequest("GET", "/dhcp", nil), "dhcp.html",
		srv.dhcpData(dhcpForm{}, st, errMsg))
	if rec.Code != http.StatusOK {
		t.Fatalf("render dhcp.html = %d: %s", rec.Code, rec.Body)
	}
	return rec.Body.String()
}

func TestDHCPTabIsLinkedAndRequiresASession(t *testing.T) {
	h, _, c, _ := loggedIn(t)
	if !strings.Contains(page(t, h, "/services", c), `href="/dhcp"`) {
		t.Error("the navigation has no DHCP link")
	}
	rec := get(t, h, "/dhcp", nil)
	if rec.Code == http.StatusOK {
		t.Errorf("anonymous GET /dhcp = %d; the lease table names devices", rec.Code)
	}
}

func TestDHCPPageSaysTheServerIsNotRunning(t *testing.T) {
	h, _, c, _ := loggedIn(t)
	body := page(t, h, "/dhcp", c)
	if !strings.Contains(strings.ToLower(body), "not running") {
		t.Errorf("page does not say the server is off:\n%s", body)
	}
}

// A fresh install has no interface chosen. That is not an error, and rendering
// an empty "DHCP cannot run here" box is the first thing most operators would
// see if it were.
func TestDHCPPageAsksForAnInterfaceRatherThanShowingABlankRefusal(t *testing.T) {
	h, _, c, _ := loggedIn(t)
	body := page(t, h, "/dhcp", c)
	if strings.Contains(body, "cannot run here") {
		t.Errorf("no interface is chosen yet, which is not a refusal:\n%s", body)
	}
	if !strings.Contains(strings.ToLower(body), "choose an interface") {
		t.Errorf("page does not ask for an interface:\n%s", body)
	}
}

func TestDHCPPageShowsTheUnsupportedReason(t *testing.T) {
	h, srv, c, _ := loggedIn(t)
	setDHCPInterface(t, srv, "lo") // never qualifies
	body := page(t, h, "/dhcp", c)
	if !strings.Contains(strings.ToLower(body), "loopback") {
		t.Errorf("page does not explain why DHCP cannot run here:\n%s", body)
	}
}

func TestDHCPPageShowsWhyTheListenerDidNotStart(t *testing.T) {
	h, _, c, _ := loggedIn(t, withDHCP(fakeDHCP{err: errNoBind}))
	body := page(t, h, "/dhcp", c)
	if !strings.Contains(body, errNoBind.Error()) {
		t.Errorf("page does not report why the listener failed:\n%s", body)
	}
}

func TestDHCPPageWarnsAboutAnotherServer(t *testing.T) {
	h, _, c, _ := loggedIn(t, withDHCP(fakeDHCP{running: true, foreign: []dhcpd.Foreign{
		{ServerID: netip.MustParseAddr("192.168.1.1"), Offered: netip.MustParseAddr("192.168.1.64")},
	}}))
	body := page(t, h, "/dhcp", c)
	for _, want := range []string{"192.168.1.1", "192.168.1.64"} {
		if !strings.Contains(body, want) {
			t.Errorf("the other DHCP server is not named (%q missing):\n%s", want, body)
		}
	}
}

func TestDHCPPageFlagsInactiveReservations(t *testing.T) {
	h, _, c, _ := loggedIn(t, withDHCP(fakeDHCP{running: true,
		problems: []dhcpd.ReservationProblem{{
			Service: "ambiguous", MAC: "aa:bb:cc:dd:ee:ff",
			Reason: "2 addresses inside the DHCP subnet",
		}}}))
	body := page(t, h, "/dhcp", c)
	for _, want := range []string{"ambiguous", "aa:bb:cc:dd:ee:ff", "2 addresses inside the DHCP subnet"} {
		if !strings.Contains(body, want) {
			t.Errorf("inactive reservation not flagged (%q missing):\n%s", want, body)
		}
	}
}

func TestDHCPPageShowsTheDualStackNote(t *testing.T) {
	_, srv := newWeb(t)
	body := renderDHCPState(t, srv, adminapi.DHCPStatus{Running: true, Supported: true, DualStack: true}, "")
	if !strings.Contains(body, "IPv6") {
		t.Errorf("no dual-stack note on a dual-stack segment:\n%s", body)
	}
	if !strings.Contains(strings.ToLower(body), "router") {
		t.Errorf("the dual-stack note does not name the workaround:\n%s", body)
	}
}

// The note describes what the running server's clients are doing, so a
// dual-stack segment with nothing listening has nothing to warn about.
func TestDHCPPageHidesTheDualStackNoteWhileNotRunning(t *testing.T) {
	_, srv := newWeb(t)
	body := renderDHCPState(t, srv, adminapi.DHCPStatus{Supported: true, DualStack: true}, "")
	if strings.Contains(body, "IPv6") {
		t.Errorf("dual-stack note shown while the server is not running:\n%s", body)
	}
}

func TestDHCPPageHidesTheDualStackNoteOnIPv4Only(t *testing.T) {
	_, srv := newWeb(t)
	body := renderDHCPState(t, srv, adminapi.DHCPStatus{Running: true, Supported: true}, "")
	if strings.Contains(body, "IPv6") {
		t.Errorf("dual-stack note shown on an IPv4-only segment:\n%s", body)
	}
}

// Qualifies does not check the subnet size and SuggestRange does, so a
// supported interface can still refuse a range. The refusal must reach the
// operator instead of being hidden behind the green flag.
func TestDHCPPageShowsASuggestErrorOnASupportedInterface(t *testing.T) {
	_, srv := newWeb(t)
	const refusal = "subnet 10.0.0.0/30 is too small to hold a DHCP range"
	body := renderDHCPState(t, srv, adminapi.DHCPStatus{Supported: true}, refusal)
	if !strings.Contains(body, refusal) {
		t.Errorf("the suggest refusal is not on the page:\n%s", body)
	}
}

// The wizard proposes; it never writes.
func TestDHCPSuggestOnAnImpossibleInterfaceExplainsAndSavesNothing(t *testing.T) {
	h, srv, c, csrf := loggedIn(t)
	rec := postForm(t, h, "/dhcp/suggest", url.Values{
		"interface": {"lo"}, "csrf_token": {csrf},
	}, c)
	if rec.Code == http.StatusSeeOther || rec.Code >= 500 {
		t.Fatalf("suggest on the loopback = %d, want the reason on the page", rec.Code)
	}
	if !strings.Contains(strings.ToLower(rec.Body.String()), "loopback") {
		t.Errorf("suggest does not say why it refused:\n%s", rec.Body)
	}
	v, err := srv.o.Settings.Get()
	if err != nil {
		t.Fatal(err)
	}
	if v.DHCPInterface != "" {
		t.Errorf("the wizard saved %q; it must only propose", v.DHCPInterface)
	}
}

// With the settings unreadable the form still has to offer a lease time the
// field will accept, or the operator's first save is rejected on a value they
// never typed.
func TestDHCPPageOffersAUsableLeaseTimeWhenSettingsAreUnread(t *testing.T) {
	h, srv, c, _ := loggedIn(t)
	srv.o.Settings = nil
	body := page(t, h, "/dhcp", c)
	if strings.Contains(body, `name="lease_seconds" type="number" min="300" max="604800" value="0"`) {
		t.Errorf("the lease time field offers 0, which min=300 rejects:\n%s", body)
	}
	if !strings.Contains(body, fmt.Sprintf(`value="%d"`, adminapi.SuggestedLeaseSeconds)) {
		t.Errorf("the lease time field does not offer the suggested default:\n%s", body)
	}
}

func TestDHCPSettingsSaveApplies(t *testing.T) {
	h, srv, c, csrf := loggedIn(t)
	rec := postForm(t, h, "/dhcp/settings", dhcpFormValues(csrf), c)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("save = %d: %s", rec.Code, rec.Body)
	}
	v, err := srv.o.Settings.Get()
	if err != nil {
		t.Fatal(err)
	}
	if !v.DHCPEnabled || v.DHCPInterface != "eth0" || v.DHCPRangeStart != "192.168.1.100" ||
		v.DHCPRangeEnd != "192.168.1.200" || v.DHCPGateway != "192.168.1.1" ||
		v.DHCPLeaseSeconds != 86400 || v.DHCPSecondaryDNS != "192.168.1.2" || !v.DHCPAllowForeign {
		t.Errorf("saved settings = %+v", v)
	}
}

// The form rebuilds the settings document, so a DHCP save must carry every
// unrelated setting through untouched.
func TestDHCPSettingsSaveKeepsUnrelatedSettings(t *testing.T) {
	h, srv, c, csrf := loggedIn(t)
	before, err := srv.o.Settings.Get()
	if err != nil {
		t.Fatal(err)
	}
	if rec := postForm(t, h, "/dhcp/settings", dhcpFormValues(csrf), c); rec.Code != http.StatusSeeOther {
		t.Fatalf("save = %d: %s", rec.Code, rec.Body)
	}
	after, err := srv.o.Settings.Get()
	if err != nil {
		t.Fatal(err)
	}
	if after.PrivateDomain != before.PrivateDomain ||
		strings.Join(after.Upstreams, ",") != strings.Join(before.Upstreams, ",") ||
		strings.Join(after.AllowQuery, ",") != strings.Join(before.AllowQuery, ",") ||
		after.TTL != before.TTL {
		t.Errorf("the DHCP save changed unrelated settings:\nbefore %+v\nafter  %+v", before, after)
	}
}

// A rejected save keeps what the operator typed: discarding a filled-in form
// over one bad field is how a range gets retyped from memory.
func TestDHCPSettingsRejectionKeepsTheTypedValues(t *testing.T) {
	h, srv, c, csrf := loggedIn(t)
	form := dhcpFormValues(csrf)
	form.Set("lease_seconds", "10")
	rec := postForm(t, h, "/dhcp/settings", form, c)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("a 10-second lease = %d, want a re-rendered form", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "dhcp_lease_seconds") {
		t.Errorf("the rejection does not name the field:\n%s", body)
	}
	if !strings.Contains(body, "192.168.1.100") {
		t.Errorf("the rejection discarded the typed range:\n%s", body)
	}
	if v, _ := srv.o.Settings.Get(); v.DHCPEnabled {
		t.Error("the rejected save was applied anyway")
	}
}

func TestDHCPReserveCreatesAServiceWithTheMAC(t *testing.T) {
	h, srv, c, csrf := loggedIn(t, withDHCP(fakeDHCP{running: true}))
	srv.o.Leases = func() []dhcp.Lease {
		return []dhcp.Lease{{Hostname: "laptop", IP: "192.168.1.50", MAC: "AA:BB:CC:DD:EE:01",
			Expires: time.Now().Add(time.Hour)}}
	}
	srv.o.DiscoveryOn = func() bool { return true }

	rec := postForm(t, h, "/dhcp/reserve", url.Values{
		"ip": {"192.168.1.50"}, "csrf_token": {csrf},
	}, c)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("reserve = %d: %s", rec.Code, rec.Body)
	}
	svcs, err := srv.o.Registry.Services()
	if err != nil {
		t.Fatal(err)
	}
	if len(svcs) != 1 || svcs[0].Name != "laptop" {
		t.Fatalf("Services() = %+v, want one reserved laptop", svcs)
	}
	if svcs[0].MAC != "aa:bb:cc:dd:ee:01" {
		t.Errorf("service MAC = %q, want the lease's MAC; without it there is no reservation", svcs[0].MAC)
	}
	if len(svcs[0].Addresses) != 1 || svcs[0].Addresses[0].Address != "192.168.1.50" {
		t.Errorf("service addresses = %+v", svcs[0].Addresses)
	}
	// The lease is now reserved, so the tab must not offer to reserve it twice.
	body := page(t, h, "/dhcp", c)
	if !strings.Contains(body, "reserved") {
		t.Errorf("the reserved lease is not marked:\n%s", body)
	}
	if strings.Contains(body, `action="/dhcp/reserve"`) {
		t.Errorf("the tab still offers to reserve a MAC a service already holds:\n%s", body)
	}
}

// The address comes from the current lease set, never from the form: a posted
// address with no lease behind it would otherwise reserve whatever it named.
func TestDHCPReserveRefusesAnAddressWithNoLease(t *testing.T) {
	h, srv, c, csrf := loggedIn(t, withDHCP(fakeDHCP{running: true}))
	srv.o.Leases = func() []dhcp.Lease { return nil }
	srv.o.DiscoveryOn = func() bool { return true }
	rec := postForm(t, h, "/dhcp/reserve", url.Values{
		"ip": {"192.168.1.77"}, "mac": {"aa:bb:cc:dd:ee:02"}, "hostname": {"attacker"},
		"csrf_token": {csrf},
	}, c)
	if rec.Code == http.StatusSeeOther {
		t.Fatal("reserving an address with no lease behind it succeeded")
	}
	if svcs, _ := srv.o.Registry.Services(); len(svcs) != 0 {
		t.Errorf("Services() = %+v, want nothing created", svcs)
	}
}

// dhcpFormValues is a complete, valid settings form.
func dhcpFormValues(csrf string) url.Values {
	return url.Values{
		"enabled": {"1"}, "interface": {"eth0"},
		"range_start": {"192.168.1.100"}, "range_end": {"192.168.1.200"},
		"gateway": {"192.168.1.1"}, "lease_seconds": {"86400"},
		"secondary_dns": {"192.168.1.2"}, "allow_foreign": {"1"},
		"csrf_token": {csrf},
	}
}
