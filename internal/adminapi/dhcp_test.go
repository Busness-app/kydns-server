package adminapi

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yoshiofthewire/kydns-server/internal/dhcpd"
	"github.com/yoshiofthewire/kydns-server/internal/registry"
	"github.com/yoshiofthewire/kydns-server/internal/store"
)

// fakeRunner is a canned runner, so a test can assert what the endpoint
// renders without a listener. A test names only the fields it asserts on.
type fakeRunner struct {
	running  bool
	err      error
	foreign  []dhcpd.Foreign
	problems []dhcpd.ReservationProblem
}

func (f fakeRunner) Status() (bool, error)                { return f.running, f.err }
func (f fakeRunner) Foreign() []dhcpd.Foreign             { return f.foreign }
func (f fakeRunner) Problems() []dhcpd.ReservationProblem { return f.problems }

// newAPIWithDHCP is newAPI plus a canned runner. A nil runner is the build
// with no DHCP at all.
func newAPIWithDHCP(t *testing.T, run DHCPRunner) (http.Handler, string) {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "kydns.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	reg := registry.New(s, "home.arpa.", func() error { return nil })
	tok, err := reg.CreateToken("test")
	if err != nil {
		t.Fatal(err)
	}
	return NewAPI(reg, nil, nil).WithDHCP(run).Handler(), tok
}

// The CLI and the UI read these keys by name, so the wire document has to
// carry all seven whatever their values are.
func TestSettingsJSONCarriesDHCPFields(t *testing.T) {
	srv, _ := testAPIWithSettings(t)

	rec := srv.do(t, "GET", "/api/v1/settings", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{
		"dhcp_enabled", "dhcp_interface", "dhcp_range_start", "dhcp_range_end",
		"dhcp_gateway", "dhcp_lease_seconds", "dhcp_secondary_dns",
	} {
		if _, ok := got[k]; !ok {
			t.Errorf("settings JSON has no %q; the CLI and UI read this", k)
		}
	}
}

func TestPatchSettingsAppliesDHCPFields(t *testing.T) {
	srv, svc := testAPIWithSettings(t)

	rec := srv.do(t, "PATCH", "/api/v1/settings", `{"dhcp_enabled":true,"dhcp_interface":"eth0",
		"dhcp_range_start":"192.168.1.100","dhcp_range_end":"192.168.1.200",
		"dhcp_gateway":"192.168.1.1","dhcp_lease_seconds":3600,
		"dhcp_secondary_dns":"1.1.1.1"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	cur, err := svc.Get()
	if err != nil {
		t.Fatal(err)
	}
	if !cur.DHCPEnabled || cur.DHCPInterface != "eth0" ||
		cur.DHCPRangeStart != "192.168.1.100" || cur.DHCPRangeEnd != "192.168.1.200" ||
		cur.DHCPGateway != "192.168.1.1" || cur.DHCPLeaseSeconds != 3600 ||
		cur.DHCPSecondaryDNS != "1.1.1.1" {
		t.Fatalf("stored settings = %+v, want every dhcp field applied", cur)
	}

	// And back out again through GET, so a field wired in one direction only
	// is caught here rather than as silent data loss.
	var got map[string]any
	if err := json.Unmarshal(srv.do(t, "GET", "/api/v1/settings", "").Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["dhcp_enabled"] != true || got["dhcp_interface"] != "eth0" ||
		got["dhcp_lease_seconds"] != float64(3600) {
		t.Errorf("settings JSON did not render the stored dhcp fields: %v", got)
	}
}

// The yaml tags are the whole point: import decodes with yaml.Unmarshal, and a
// field with no yaml tag decodes from its lowercased Go name, which would
// blank every dhcp setting on a restore.
func TestSettingsExportImportRoundTripKeepsDHCP(t *testing.T) {
	srv, svc := testAPIWithSettings(t)

	if rec := srv.do(t, "PATCH", "/api/v1/settings", `{"dhcp_enabled":true,"dhcp_interface":"eth0",
		"dhcp_range_start":"192.168.1.100","dhcp_range_end":"192.168.1.200",
		"dhcp_gateway":"192.168.1.1","dhcp_lease_seconds":3600,
		"dhcp_secondary_dns":"9.9.9.9"}`); rec.Code != http.StatusOK {
		t.Fatalf("setup patch: %d %s", rec.Code, rec.Body)
	}
	doc := srv.do(t, "GET", "/api/v1/export", "").Body.String()
	if !strings.Contains(doc, "dhcp_interface") {
		t.Fatalf("the export document has no dhcp_interface:\n%s", doc)
	}

	if rec := srv.do(t, "PATCH", "/api/v1/settings", `{"dhcp_enabled":false,"dhcp_interface":"",
		"dhcp_range_start":"","dhcp_range_end":"","dhcp_gateway":"",
		"dhcp_lease_seconds":86400,"dhcp_secondary_dns":""}`); rec.Code != http.StatusOK {
		t.Fatalf("setup clear: %d %s", rec.Code, rec.Body)
	}
	if rec := srv.do(t, "POST", "/api/v1/import", doc); rec.Code >= 300 {
		t.Fatalf("import: %d %s", rec.Code, rec.Body)
	}

	cur, err := svc.Get()
	if err != nil {
		t.Fatal(err)
	}
	if !cur.DHCPEnabled || cur.DHCPInterface != "eth0" ||
		cur.DHCPRangeStart != "192.168.1.100" || cur.DHCPRangeEnd != "192.168.1.200" ||
		cur.DHCPGateway != "192.168.1.1" || cur.DHCPLeaseSeconds != 3600 ||
		cur.DHCPSecondaryDNS != "9.9.9.9" {
		t.Fatalf("round trip lost dhcp settings: %+v", cur)
	}
}

// A build with no runner reports not running rather than failing: every test
// that constructs an API without one still has to work.
func TestDHCPStatusWithoutARunner(t *testing.T) {
	h, tok := newAPIWithDHCP(t, nil)

	rec := do(t, h, "GET", "/api/v1/dhcp/status", tok, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200 even with no runner: %s", rec.Code, rec.Body)
	}
	var got struct {
		Running  bool            `json:"running"`
		Error    string          `json:"error"`
		Foreign  json.RawMessage `json:"foreign"`
		Problems json.RawMessage `json:"problems"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Running {
		t.Error("running = true with no runner wired")
	}
	if got.Error != "" {
		t.Errorf("error = %q, want none: nothing failed", got.Error)
	}
	// The UI ranges over both, so a null here is a broken tab rather than an
	// empty table. This is the build most likely to emit one.
	if string(got.Foreign) != "[]" || string(got.Problems) != "[]" {
		t.Errorf("foreign=%s problems=%s, want [] and [] rather than null", got.Foreign, got.Problems)
	}
}

func TestDHCPStatusRunning(t *testing.T) {
	h, tok := newAPIWithDHCP(t, fakeRunner{running: true})

	var got struct {
		Running bool `json:"running"`
	}
	rec := do(t, h, "GET", "/api/v1/dhcp/status", tok, "")
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Running {
		t.Errorf("running = false with a running listener: %s", rec.Body)
	}
}

// "Off" and "refused to start" are different answers, and only the second one
// has a reason an operator can act on.
func TestDHCPStatusReportsWhyItIsNotRunning(t *testing.T) {
	const reason = "another DHCP server is already answering on this network: 192.168.1.1"
	h, tok := newAPIWithDHCP(t, fakeRunner{err: errors.New(reason)})

	rec := do(t, h, "GET", "/api/v1/dhcp/status", tok, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200: %s", rec.Code, rec.Body)
	}
	var got struct {
		Running bool   `json:"running"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Running {
		t.Error("running = true when the listener refused to start")
	}
	if got.Error != reason {
		t.Errorf("error = %q, want %q", got.Error, reason)
	}
}

// Whether DHCP is running names the network this node serves, so it sits
// behind the same bearer token as every other endpoint.
func TestDHCPStatusRequiresAuth(t *testing.T) {
	h, _ := newAPIWithDHCP(t, nil)

	if rec := do(t, h, "GET", "/api/v1/dhcp/status", "", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", rec.Code)
	}
}

// A replica refuses administrative writes with the address of the node to make
// them on. DHCP settings are node-local, but they are still a settings write.
func TestDHCPSettingsRejectedOnAReplica(t *testing.T) {
	const primary = "10.0.0.2:8443"
	h, tok := replicaOf(t, primary)

	rec := do(t, h, "PATCH", "/api/v1/settings", tok, `{"dhcp_enabled":true}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status %d, want 409: a replica accepted a settings write", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), primary) {
		t.Errorf("the refusal does not name the primary: %s", rec.Body)
	}
}

// The tab reads unresolved reservations and other DHCP servers from the same
// request as running/error, so one poll answers everything it shows.
func TestDHCPStatusReportsProblemsAndForeignServers(t *testing.T) {
	h, tok := newAPIWithDHCP(t, fakeRunner{
		running: true,
		foreign: []dhcpd.Foreign{
			{ServerID: netip.MustParseAddr("192.168.1.1"), Offered: netip.MustParseAddr("192.168.1.55")},
			// An OFFER can carry no address at all.
			{ServerID: netip.MustParseAddr("192.168.1.2")},
		},
		problems: []dhcpd.ReservationProblem{{
			Service: "kypost", MAC: "aa:bb:cc:dd:ee:ff",
			Reason: "kypost has no address inside the DHCP subnet",
		}},
	})

	rec := do(t, h, "GET", "/api/v1/dhcp/status", tok, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	var got struct {
		Running bool `json:"running"`
		Foreign []struct {
			Server  string `json:"server"`
			Offered string `json:"offered"`
		} `json:"foreign"`
		Problems []struct {
			Service string `json:"service"`
			MAC     string `json:"mac"`
			Reason  string `json:"reason"`
		} `json:"problems"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Running {
		t.Errorf("running = false: %s", rec.Body)
	}
	if len(got.Foreign) != 2 || got.Foreign[0].Server != "192.168.1.1" || got.Foreign[0].Offered != "192.168.1.55" {
		t.Fatalf("foreign = %+v, want the other server and what it offered", got.Foreign)
	}
	if got.Foreign[1].Offered != "" {
		t.Errorf("offered = %q for an OFFER with no address, want blank", got.Foreign[1].Offered)
	}
	if len(got.Problems) != 1 || got.Problems[0].Service != "kypost" ||
		got.Problems[0].MAC != "aa:bb:cc:dd:ee:ff" ||
		!strings.Contains(got.Problems[0].Reason, "DHCP subnet") {
		t.Fatalf("problems = %+v, want the unresolved reservation and why", got.Problems)
	}
}

// An interface that cannot serve DHCP is not an error, it is the answer: the
// tab renders the reason in place of the form.
func TestDHCPStatusReportsWhyTheInterfaceCannotServeDHCP(t *testing.T) {
	srv, _ := testAPIWithSettings(t)
	// Loopback is never a qualifying DHCP interface, so this asserts the
	// refusal path rather than depending on the host's interfaces.
	if rec := srv.do(t, "PATCH", "/api/v1/settings", `{"dhcp_interface":"lo"}`); rec.Code != http.StatusOK {
		t.Fatalf("setup patch: %d %s", rec.Code, rec.Body)
	}

	rec := srv.do(t, "GET", "/api/v1/dhcp/status", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	var got struct {
		Supported bool   `json:"supported"`
		Reason    string `json:"reason"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Supported {
		t.Error("supported = true for the loopback")
	}
	if !strings.Contains(got.Reason, "loopback") {
		t.Errorf("reason = %q; the operator sees this verbatim", got.Reason)
	}
}

func TestDHCPSuggestRefusesAnInterfaceThatCannotServeDHCP(t *testing.T) {
	h, tok := newAPI(t)

	rec := do(t, h, "GET", "/api/v1/dhcp/suggest?interface=lo", tok, "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for an interface that cannot serve DHCP: %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "loopback") {
		t.Fatalf("body %q does not say why; the wizard shows this verbatim", rec.Body)
	}
}

func TestDHCPSuggestRejectsAnUnknownInterface(t *testing.T) {
	h, tok := newAPI(t)

	if rec := do(t, h, "GET", "/api/v1/dhcp/suggest?interface=definitely-not-real0", tok, ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body)
	}
	if rec := do(t, h, "GET", "/api/v1/dhcp/suggest", tok, ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("no interface at all = %d, want 400: %s", rec.Code, rec.Body)
	}
}

// Which interfaces exist and what they address names this network, so the
// prefill sits behind the same bearer token as everything else.
func TestDHCPSuggestRequiresAuth(t *testing.T) {
	h, _ := newAPI(t)

	if rec := do(t, h, "GET", "/api/v1/dhcp/suggest?interface=lo", "", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", rec.Code)
	}
}

// The wizard's whole prefill, against a real interface. Skipped where the
// host has none that can serve DHCP, which is every bridge-mode container.
func TestDHCPSuggestFillsInTheForm(t *testing.T) {
	name := qualifyingInterface(t)
	h, tok := newAPI(t)

	rec := do(t, h, "GET", "/api/v1/dhcp/suggest?interface="+name, tok, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	var got struct {
		Interface    string `json:"interface"`
		Subnet       string `json:"subnet"`
		RangeStart   string `json:"range_start"`
		RangeEnd     string `json:"range_end"`
		LeaseSeconds int    `json:"lease_seconds"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Interface != name {
		t.Errorf("interface = %q, want %q", got.Interface, name)
	}
	subnet, err := netip.ParsePrefix(got.Subnet)
	if err != nil {
		t.Fatalf("subnet %q: %v", got.Subnet, err)
	}
	start, err := netip.ParseAddr(got.RangeStart)
	if err != nil {
		t.Fatalf("range_start %q: %v", got.RangeStart, err)
	}
	end, err := netip.ParseAddr(got.RangeEnd)
	if err != nil {
		t.Fatalf("range_end %q: %v", got.RangeEnd, err)
	}
	// The operator confirms this form as-is, so a range outside the subnet or
	// running backwards would be applied exactly as suggested.
	if !subnet.Contains(start) || !subnet.Contains(end) || start.Compare(end) >= 0 {
		t.Errorf("range %v-%v is not an ascending range inside %v", start, end, subnet)
	}
	if got.LeaseSeconds != 86400 {
		t.Errorf("lease_seconds = %d, want a day", got.LeaseSeconds)
	}
}

// qualifyingInterface finds an interface DHCP could actually run on, or skips.
func qualifyingInterface(t *testing.T) string {
	t.Helper()
	ifs, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range ifs {
		if dhcpd.Qualifies(i.Name) == nil {
			return i.Name
		}
	}
	t.Skip("no interface on this host can serve DHCP")
	return ""
}
