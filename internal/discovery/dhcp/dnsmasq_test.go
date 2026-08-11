package dhcp

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The fixture's live leases expire at unix 1786000000; anchor "now" before it.
var testNow = time.Unix(1_700_000_000, 0)

func parseFixture(t *testing.T) ([]Lease, []string) {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", "dnsmasq.leases"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	return ParseDnsmasq(f, testNow)
}

func byHostname(leases []Lease) map[string]Lease {
	m := map[string]Lease{}
	for _, l := range leases {
		m[l.Hostname] = l
	}
	return m
}

func TestParsesValidLease(t *testing.T) {
	leases, _ := parseFixture(t)
	got, ok := byHostname(leases)["kypost"]
	if !ok {
		t.Fatalf("kypost not parsed; got %+v", leases)
	}
	if got.IP != "192.168.1.20" {
		t.Errorf("IP = %q, want 192.168.1.20", got.IP)
	}
	if got.MAC != "aa:bb:cc:dd:ee:01" {
		t.Errorf("MAC = %q", got.MAC)
	}
}

// Discovery sources are untrusted configuration input, so junk is skipped and
// reported, never silently rewritten into something that looks valid.
func TestSkipsJunkHostnames(t *testing.T) {
	leases, skipped := parseFixture(t)
	names := byHostname(leases)
	for _, unwanted := range []string{"*", "", "host_with_underscore", "has.a.dot"} {
		if _, present := names[unwanted]; present {
			t.Errorf("hostname %q was accepted, want it skipped", unwanted)
		}
	}
	if len(skipped) == 0 {
		t.Fatal("skipped reasons are empty, want the junk lines reported")
	}
	joined := strings.Join(skipped, "\n")
	for _, want := range []string{"host_with_underscore", "has.a.dot", "not-an-ip"} {
		if !strings.Contains(joined, want) {
			t.Errorf("skipped reasons do not mention %q:\n%s", want, joined)
		}
	}
}

func TestLowercasesHostnames(t *testing.T) {
	leases, _ := parseFixture(t)
	if _, ok := byHostname(leases)["living-room-tv"]; !ok {
		t.Errorf("Living-Room-TV was not lowercased; got %+v", leases)
	}
}

func TestDropsExpiredLeases(t *testing.T) {
	leases, _ := parseFixture(t)
	if _, ok := byHostname(leases)["expired-host"]; ok {
		t.Error("an expired lease was returned")
	}
}

// Two MACs claiming one hostname: the newest lease wins and the conflict is
// reported.
func TestDuplicateHostnameNewestWins(t *testing.T) {
	leases, skipped := parseFixture(t)
	nas, ok := byHostname(leases)["nas"]
	if !ok {
		t.Fatal("nas missing")
	}
	if nas.IP != "192.168.1.27" {
		t.Errorf("nas IP = %q, want the newer lease 192.168.1.27", nas.IP)
	}
	if !strings.Contains(strings.Join(skipped, "\n"), "nas") {
		t.Error("the duplicate hostname conflict was not reported")
	}
	count := 0
	for _, l := range leases {
		if l.Hostname == "nas" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("nas appears %d times, want 1", count)
	}
}

func TestSkipsMalformedLines(t *testing.T) {
	leases, _ := parseFixture(t)
	if _, ok := byHostname(leases)["badaddr"]; ok {
		t.Error("a lease with an invalid IP was accepted")
	}
}

func TestParsesIPv6Lease(t *testing.T) {
	leases, _ := parseFixture(t)
	got, ok := byHostname(leases)["v6host"]
	if !ok {
		t.Fatalf("v6host missing; got %+v", leases)
	}
	if got.IP != "fd00::5" {
		t.Errorf("IP = %q, want fd00::5", got.IP)
	}
}

// dnsmasq writes 0 for an infinite lease; it must not be treated as expired.
func TestInfiniteLeaseNotExpired(t *testing.T) {
	body := "0 aa:bb:cc:dd:ee:0b 192.168.1.28 forever 01:aa\n"
	leases, _ := ParseDnsmasq(strings.NewReader(body), testNow)
	if len(leases) != 1 || leases[0].Hostname != "forever" {
		t.Errorf("ParseDnsmasq() = %+v, want the infinite lease kept", leases)
	}
}

func TestSkipsCommentsAndBlankLines(t *testing.T) {
	body := "# a comment\n\n1786000000 aa:bb:cc:dd:ee:0c 192.168.1.29 real 01:aa\n"
	leases, skipped := ParseDnsmasq(strings.NewReader(body), testNow)
	if len(leases) != 1 {
		t.Errorf("leases = %+v, want just the real one", leases)
	}
	if len(skipped) != 0 {
		t.Errorf("skipped = %v, want comments and blanks ignored silently", skipped)
	}
}

// An unreadable lease file is an error the caller handles by keeping the last
// known leases; it must never be a panic or a silent empty list.
func TestSourceMissingFileErrors(t *testing.T) {
	d := &DnsmasqSource{Path: filepath.Join(t.TempDir(), "absent.leases")}
	if _, err := d.Leases(context.Background()); err == nil {
		t.Error("Leases() error = nil for a missing file, want an error")
	}
}

func TestSourceReadsFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "dnsmasq.leases")
	body := "1786000000 aa:bb:cc:dd:ee:01 192.168.1.20 kypost 01:aa\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	d := &DnsmasqSource{Path: p, Now: func() time.Time { return testNow }}
	leases, err := d.Leases(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(leases) != 1 || leases[0].Hostname != "kypost" {
		t.Errorf("Leases() = %+v", leases)
	}
	if d.Name() == "" {
		t.Error("Name() is empty")
	}
}

// The parser emits a stable order, which the poller's digest relies on.
func TestOrderIsStable(t *testing.T) {
	first, _ := parseFixture(t)
	second, _ := parseFixture(t)
	if len(first) != len(second) {
		t.Fatalf("lengths differ: %d vs %d", len(first), len(second))
	}
	for i := range first {
		if first[i].Hostname != second[i].Hostname {
			t.Fatalf("order differs at %d: %q vs %q", i, first[i].Hostname, second[i].Hostname)
		}
	}
}
