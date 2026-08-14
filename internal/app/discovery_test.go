package app

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// leaseFile writes a dnsmasq lease file with a far-future expiry.
func leaseFile(t *testing.T, dir string, lines ...string) string {
	t.Helper()
	p := filepath.Join(dir, "dnsmasq.leases")
	var body string
	for _, l := range lines {
		body += l + "\n"
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func resolveA(t *testing.T, server, name string) []string {
	t.Helper()
	out, err := lookupA(server, name)
	if err != nil {
		t.Fatalf("resolve %s: %v", name, err)
	}
	return out
}

// lookupA is the same query without the assertion, for callers that are
// waiting for a server to come up rather than testing one that has.
func lookupA(server, name string) ([]string, error) {
	c := &dns.Client{Net: "udp", Timeout: 3 * time.Second}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	resp, _, err := c.Exchange(m, server)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, rr := range resp.Answer {
		if a, ok := rr.(*dns.A); ok {
			out = append(out, a.A.String())
		}
	}
	return out, nil
}

// A DHCP lease resolves over DNS without any manual registration.
func TestEndToEndLeaseResolves(t *testing.T) {
	dir := t.TempDir()
	lf := leaseFile(t, dir, "4102444800 aa:bb:cc:dd:ee:01 192.168.1.50 laptop 01:aa")
	cfg, dnsPort, adminPort := writeConfig(t, dir,
		fmt.Sprintf("discovery:\n  dhcp_lease_file: %s\n  interval: 1\n", lf))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go Serve(ctx, cfg, nil)
	waitForHTTP(t, fmt.Sprintf("http://127.0.0.1:%d/api/v1/healthz", adminPort))

	server := fmt.Sprintf("127.0.0.1:%d", dnsPort)
	var got []string
	for i := 0; i < 60; i++ {
		if got = resolveA(t, server, "laptop.home.arpa."); len(got) == 1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(got) != 1 || got[0] != "192.168.1.50" {
		t.Fatalf("laptop.home.arpa = %v, want the lease address", got)
	}
}

// A service outranks a lease with the same name; the lease is shadowed.
func TestEndToEndServiceShadowsLease(t *testing.T) {
	dir := t.TempDir()
	lf := leaseFile(t, dir, "4102444800 aa:bb:cc:dd:ee:01 192.168.1.50 kypost 01:aa")
	cfg, dnsPort, adminPort := writeConfig(t, dir,
		fmt.Sprintf("discovery:\n  dhcp_lease_file: %s\n  interval: 1\n", lf))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go Serve(ctx, cfg, nil)

	base := fmt.Sprintf("http://127.0.0.1:%d", adminPort)
	waitForHTTP(t, base+"/api/v1/healthz")
	token := waitForFile(t, filepath.Join(dir, "bootstrap-token"))
	postJSON(t, base+"/api/v1/services", token,
		`{"name":"kypost","addresses":[{"address":"192.168.1.20"}]}`)

	got := resolveA(t, fmt.Sprintf("127.0.0.1:%d", dnsPort), "kypost.home.arpa.")
	if len(got) != 1 || got[0] != "192.168.1.20" {
		t.Errorf("kypost.home.arpa = %v, want the service address to win", got)
	}
}

// With no lease file configured, discovery stays off and the server is fine.
func TestDiscoveryOffByDefault(t *testing.T) {
	dir := t.TempDir()
	cfg, dnsPort, adminPort := writeConfig(t, dir, "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go Serve(ctx, cfg, nil)
	waitForHTTP(t, fmt.Sprintf("http://127.0.0.1:%d/api/v1/healthz", adminPort))

	if got := resolveA(t, fmt.Sprintf("127.0.0.1:%d", dnsPort), "laptop.home.arpa."); len(got) != 0 {
		t.Errorf("= %v, want nothing resolved with discovery off", got)
	}
}

// An unreadable lease file must not stop the server from starting or serving.
func TestUnreadableLeaseFileDoesNotBreakServing(t *testing.T) {
	dir := t.TempDir()
	cfg, dnsPort, adminPort := writeConfig(t, dir,
		fmt.Sprintf("discovery:\n  dhcp_lease_file: %s\n  interval: 1\n",
			filepath.Join(dir, "absent.leases")))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go Serve(ctx, cfg, nil)

	base := fmt.Sprintf("http://127.0.0.1:%d", adminPort)
	waitForHTTP(t, base+"/api/v1/healthz")
	token := waitForFile(t, filepath.Join(dir, "bootstrap-token"))
	postJSON(t, base+"/api/v1/services", token,
		`{"name":"nas","addresses":[{"address":"192.168.1.30"}]}`)

	got := resolveA(t, fmt.Sprintf("127.0.0.1:%d", dnsPort), "nas.home.arpa.")
	if len(got) != 1 {
		t.Errorf("= %v, want the server still answering with a missing lease file", got)
	}
}
