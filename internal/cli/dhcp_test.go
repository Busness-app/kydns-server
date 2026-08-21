package cli

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// dhcpServer answers the two endpoints the command reads. Anything else is a
// test bug, not a 404 to be papered over.
func dhcpServer(t *testing.T, status, leases string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/dhcp/status":
			w.Write([]byte(status))
		case "/api/v1/leases":
			w.Write([]byte(leases))
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// A command missing from Commands is unreachable from the compiled binary,
// which has already happened twice.
func TestDHCPCommandIsRegistered(t *testing.T) {
	if Lookup("dhcp") == nil {
		t.Fatal("kydns dhcp is not in Commands, so the binary cannot run it")
	}
}

func TestDHCPStatusPrintsTheReason(t *testing.T) {
	srv := dhcpServer(t, `{"running":false,"error":"interface eth9 has no IPv4 address"}`, `{"leases":[]}`)

	var out, errOut bytes.Buffer
	if code := dhcpCmd(clientFor(srv), []string{"status"}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "interface eth9 has no IPv4 address") {
		t.Errorf("the reason is missing:\n%s", out.String())
	}
}

func TestDHCPStatusRunning(t *testing.T) {
	srv := dhcpServer(t, `{"running":true}`, `{"leases":[]}`)

	var out, errOut bytes.Buffer
	if code := dhcpCmd(clientFor(srv), []string{"status"}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "yes") {
		t.Errorf("a running server does not read as running:\n%s", out.String())
	}
}

func TestDHCPLeasesPrintsATable(t *testing.T) {
	srv := dhcpServer(t, `{"running":true}`,
		`{"leases":[{"hostname":"laptop","address":"192.168.1.50","mac":"aa:bb:cc:dd:ee:01","expires":4102444800}]}`)

	var out, errOut bytes.Buffer
	if code := dhcpCmd(clientFor(srv), []string{"leases"}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	for _, want := range []string{
		"laptop", "192.168.1.50", "aa:bb:cc:dd:ee:01",
		time.Unix(4102444800, 0).Format(time.RFC3339),
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output is missing %q:\n%s", want, out.String())
		}
	}
	// The API sends Unix seconds; a raw integer is not a date an operator reads.
	if strings.Contains(out.String(), "4102444800") {
		t.Errorf("the expiry printed as raw Unix seconds:\n%s", out.String())
	}
}

// An operator who turned DHCP on and sees nothing needs the reason, not a
// blank screen.
func TestDHCPLeasesEmptyExplainsWhy(t *testing.T) {
	srv := dhcpServer(t, `{"running":false,"error":"another DHCP server is already answering"}`, `{"leases":[]}`)

	var out, errOut bytes.Buffer
	if code := dhcpCmd(clientFor(srv), []string{"leases"}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "another DHCP server is already answering") {
		t.Errorf("an empty lease list did not say why:\n%s", out.String())
	}
}

func TestDHCPUnknownSubcommand(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := dhcpCmd(&Client{}, []string{"nonsense"}, &out, &errOut); code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if code := dhcpCmd(&Client{}, nil, &out, &errOut); code != 2 {
		t.Fatalf("exit %d with no subcommand, want 2", code)
	}
}
