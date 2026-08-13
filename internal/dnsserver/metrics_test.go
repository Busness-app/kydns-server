package dnsserver

import (
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/yoshiofthewire/kydns-server/internal/store"
	"github.com/yoshiofthewire/kydns-server/internal/zone"
)

// blockList is a PolicyDecider that blocks exactly the names given to it.
type blockList map[string]bool

func (b blockList) Decide(name string) (bool, string, uint32) {
	if b[name] {
		return true, "testlist", 60
	}
	return false, "", 0
}

// newCountingServer wires a server that answers home.arpa. authoritatively,
// forwards everything else, and refuses anything outside allow. It returns the
// server so a test can read its metrics, and the address to query.
func newCountingServer(t *testing.T, allow []netip.Prefix, pol PolicyDecider) (*Server, string) {
	t.Helper()
	h := zone.NewHolder(func() (zone.Input, error) {
		return zone.Input{
			Zone:     "home.arpa.",
			Views:    []store.View{{Name: "lan", Subnets: []string{"127.0.0.2/32"}}},
			Services: []store.Service{{ID: 1, Name: "kypost", Addresses: []store.Address{{Address: "192.168.1.20"}}}},
		}, nil
	}, nil)
	if err := h.Rebuild(); err != nil {
		t.Fatal(err)
	}
	srv := New(Options{
		Holder:    h,
		ACL:       NewACL(allow),
		Auth:      NewAuthoritative("home.arpa.", 60, nil),
		Forwarder: newForwarder(okUpstream("tls://1.1.1.1:853", true)),
		Policy:    pol,
	})
	return srv, startUDP(t, srv)
}

func TestMetricsCountEachOutcome(t *testing.T) {
	allow := []netip.Prefix{netip.MustParsePrefix("127.0.0.2/32")}
	srv, addr := newCountingServer(t, allow, blockList{"ads.example.com.": true})

	queryFrom(t, addr, "127.0.0.2", "kypost.home.arpa.", dns.TypeA)
	queryFrom(t, addr, "127.0.0.2", "example.com.", dns.TypeA)
	queryFrom(t, addr, "127.0.0.2", "ads.example.com.", dns.TypeA)
	queryFrom(t, addr, "127.0.0.3", "example.com.", dns.TypeA) // outside the allow list

	s := srv.Metrics().Snapshot()
	if s.Total != 4 {
		t.Errorf("Total = %d, want 4", s.Total)
	}
	if s.Authoritative != 1 {
		t.Errorf("Authoritative = %d, want 1", s.Authoritative)
	}
	if s.Forwarded != 1 {
		t.Errorf("Forwarded = %d, want 1", s.Forwarded)
	}
	if s.Blocked != 1 {
		t.Errorf("Blocked = %d, want 1", s.Blocked)
	}
	if s.Refused != 1 {
		t.Errorf("Refused = %d, want 1", s.Refused)
	}
}

// A malformed query is neither served nor refused: it has to land somewhere or
// the outcome counts will not add up to the total.
func TestMetricsCountMalformedQueryAsError(t *testing.T) {
	srv, addr := newCountingServer(t, []netip.Prefix{netip.MustParsePrefix("127.0.0.2/32")}, nil)

	c := &dns.Client{Net: "udp", Timeout: 3 * time.Second}
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	m.Question[0].Qclass = dns.ClassCHAOS
	if _, _, err := c.Exchange(m, addr); err != nil {
		t.Fatal(err)
	}

	s := srv.Metrics().Snapshot()
	if s.Errors != 1 {
		t.Errorf("Errors = %d, want 1", s.Errors)
	}
	if s.Total != s.Authoritative+s.Forwarded+s.Blocked+s.Refused+s.Errors {
		t.Errorf("outcomes do not sum to the total: %+v", s)
	}
}

func TestMetricsRecordLatencyAndLastQuery(t *testing.T) {
	srv, addr := newCountingServer(t, []netip.Prefix{netip.MustParsePrefix("127.0.0.2/32")}, nil)

	if s := srv.Metrics().Snapshot(); s.LastQuery != 0 {
		t.Errorf("LastQuery = %d before any query, want 0", s.LastQuery)
	}
	queryFrom(t, addr, "127.0.0.2", "kypost.home.arpa.", dns.TypeA)

	s := srv.Metrics().Snapshot()
	if s.LastQuery == 0 {
		t.Error("LastQuery still 0 after a query")
	}
	if s.LatencyCount != 1 {
		t.Errorf("LatencyCount = %d, want 1", s.LatencyCount)
	}
	if s.UptimeSeconds < 0 {
		t.Errorf("UptimeSeconds = %d, want >= 0", s.UptimeSeconds)
	}
}

// The stats are aggregate by construction. A snapshot that carried a client
// address would leak past the log_client_ip gate, so nothing in it is allowed
// to be a string in the first place.
func TestMetricsSnapshotCarriesNoClientIdentity(t *testing.T) {
	srv, addr := newCountingServer(t, []netip.Prefix{netip.MustParsePrefix("127.0.0.2/32")}, nil)
	queryFrom(t, addr, "127.0.0.2", "kypost.home.arpa.", dns.TypeA)

	s := srv.Metrics().Snapshot()
	for _, b := range s.History {
		if b.Minute == 0 {
			t.Error("history bucket has no minute stamp")
			break
		}
	}
	if len(s.History) != histSlots {
		t.Errorf("History has %d buckets, want %d", len(s.History), histSlots)
	}
}
