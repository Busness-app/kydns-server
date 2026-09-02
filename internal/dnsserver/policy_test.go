package dnsserver

import (
	"net/netip"
	"testing"

	"github.com/Busness-app/kydns-server/internal/store"
	"github.com/Busness-app/kydns-server/internal/zone"
	"github.com/miekg/dns"
)

// stubPolicy blocks exactly the names it is given.
type stubPolicy struct {
	blocked map[string]string
	calls   int
}

func (s *stubPolicy) Decide(name string) (bool, string, uint32) {
	s.calls++
	if list, ok := s.blocked[dns.Fqdn(name)]; ok {
		return true, list, 60
	}
	return false, "forwarded", 0
}

// newPolicyServer wires a server with one local service and a stub policy, and
// returns the address, the upstream (to count leaks) and the policy.
func newPolicyServer(t *testing.T, blocked map[string]string) (string, *fakeUpstream, *stubPolicy) {
	t.Helper()
	h := zone.NewHolder(func() (zone.Input, error) {
		return zone.Input{
			Zone: "home.arpa.",
			Services: []store.Service{{
				ID: 1, Name: "kypost",
				Addresses: []store.Address{{Address: "192.168.1.20"}},
			}},
		}, nil
	}, nil)
	if err := h.Rebuild(); err != nil {
		t.Fatal(err)
	}
	up := okUpstream("tls://1.1.1.1:853", true)
	pol := &stubPolicy{blocked: blocked}
	addr := startUDP(t, New(Options{
		Holder:    h,
		ACL:       NewACL([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}),
		Auth:      NewAuthoritative("home.arpa.", 60, nil),
		Forwarder: newForwarder(up),
		Policy:    pol,
	}))
	return addr, up, pol
}

func TestBlockedNameReturnsLocalNXDOMAIN(t *testing.T) {
	addr, up, _ := newPolicyServer(t, map[string]string{"ads.example.": "steven-black"})
	m := queryFrom(t, addr, "127.0.0.1", "ads.example.", dns.TypeA)
	if m.Rcode != dns.RcodeNameError {
		t.Errorf("rcode = %s, want NXDOMAIN", dns.RcodeToString[m.Rcode])
	}
	if m.Authoritative {
		t.Error("the AA bit is set on a blocked answer, want it clear")
	}
	if len(m.Answer) != 0 {
		t.Errorf("answer = %v, want empty", m.Answer)
	}
	// The whole point: the query never left the building.
	if n := up.calls.Load(); n != 0 {
		t.Errorf("upstream saw %d queries for a blocked name, want 0", n)
	}
}

func TestBlockedAnswerCarriesTheBlockTTL(t *testing.T) {
	addr, _, _ := newPolicyServer(t, map[string]string{"ads.example.": "steven-black"})
	m := queryFrom(t, addr, "127.0.0.1", "ads.example.", dns.TypeA)
	if len(m.Ns) != 1 {
		t.Fatalf("authority = %v, want one SOA so the client caches the block", m.Ns)
	}
	soa, ok := m.Ns[0].(*dns.SOA)
	if !ok {
		t.Fatalf("authority = %T, want *dns.SOA", m.Ns[0])
	}
	if soa.Minttl != 60 || soa.Hdr.Ttl != 60 {
		t.Errorf("SOA ttl/minttl = %d/%d, want 60/60", soa.Hdr.Ttl, soa.Minttl)
	}
}

func TestUnblockedNameStillForwards(t *testing.T) {
	addr, up, _ := newPolicyServer(t, nil)
	m := queryFrom(t, addr, "127.0.0.1", "example.org.", dns.TypeA)
	if m.Rcode != dns.RcodeSuccess || len(m.Answer) == 0 {
		t.Errorf("= %s with %d answers, want a forwarded answer", dns.RcodeToString[m.Rcode], len(m.Answer))
	}
	if n := up.calls.Load(); n != 1 {
		t.Errorf("upstream saw %d queries, want 1", n)
	}
}

// A local service is answered authoritatively and the policy is never
// consulted, so a public list can never blackhole it.
func TestLocalServiceIsNeverOfferedToThePolicy(t *testing.T) {
	addr, _, pol := newPolicyServer(t, map[string]string{"kypost.home.arpa.": "steven-black"})
	m := queryFrom(t, addr, "127.0.0.1", "kypost.home.arpa.", dns.TypeA)
	if m.Rcode != dns.RcodeSuccess || len(m.Answer) != 1 {
		t.Fatalf("= %s with %d answers, want the local address", dns.RcodeToString[m.Rcode], len(m.Answer))
	}
	if !m.Authoritative {
		t.Error("the AA bit is clear on a local answer")
	}
	if pol.calls != 0 {
		t.Errorf("the policy was consulted %d times for a local name, want 0", pol.calls)
	}
}

func TestNilPolicyForwardsEverything(t *testing.T) {
	h := zone.NewHolder(func() (zone.Input, error) {
		return zone.Input{Zone: "home.arpa."}, nil
	}, nil)
	if err := h.Rebuild(); err != nil {
		t.Fatal(err)
	}
	up := okUpstream("tls://1.1.1.1:853", true)
	addr := startUDP(t, New(Options{
		Holder:    h,
		ACL:       NewACL([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}),
		Auth:      NewAuthoritative("home.arpa.", 60, nil),
		Forwarder: newForwarder(up),
	}))
	if m := queryFrom(t, addr, "127.0.0.1", "example.org.", dns.TypeA); m.Rcode != dns.RcodeSuccess {
		t.Errorf("= %s, want success with no policy wired", dns.RcodeToString[m.Rcode])
	}
}
