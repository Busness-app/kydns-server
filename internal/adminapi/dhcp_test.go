package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yoshiofthewire/kydns-server/internal/registry"
	"github.com/yoshiofthewire/kydns-server/internal/store"
)

// newAPIWithDHCP is newAPI plus a canned runner status, so a test can assert
// what the endpoint renders without a listener. A nil status is the build with
// no DHCP runner at all.
func newAPIWithDHCP(t *testing.T, status func() (bool, error)) (http.Handler, string) {
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
	api := NewAPI(reg, nil, nil)
	if status != nil {
		api = api.WithDHCP(status)
	}
	return api.Handler(), tok
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
		Running bool   `json:"running"`
		Error   string `json:"error"`
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
}

func TestDHCPStatusRunning(t *testing.T) {
	h, tok := newAPIWithDHCP(t, func() (bool, error) { return true, nil })

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
	h, tok := newAPIWithDHCP(t, func() (bool, error) { return false, errors.New(reason) })

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
