package dnsserver

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/yoshiofthewire/kydns-server/internal/store"
	"github.com/yoshiofthewire/kydns-server/internal/zone"
)

// startUDP runs srv on an ephemeral loopback UDP port and returns its address.
func startUDP(t *testing.T, srv *Server) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ds := &dns.Server{PacketConn: pc, Handler: srv}
	go ds.ActivateAndServe()
	t.Cleanup(func() { ds.Shutdown() })
	return pc.LocalAddr().String()
}

// newTestServer wires a server whose views match the /32 loopback addresses
// the tests dial from.
func newTestServer(t *testing.T, allow []netip.Prefix) string {
	t.Helper()
	h := zone.NewHolder(func() (zone.Input, error) {
		return zone.Input{
			Zone:         "home.arpa.",
			ReverseZones: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
			Views: []store.View{
				{Name: "lan", Subnets: []string{"127.0.0.2/32"}},
				{Name: "tailnet", Subnets: []string{"127.0.0.3/32"}},
			},
			Services: []store.Service{{
				ID: 1, Name: "kypost",
				Addresses: []store.Address{
					{Address: "192.168.1.20"},
					{Address: "100.101.102.103", View: "tailnet"},
				},
			}},
		}, nil
	})
	if err := h.Rebuild(); err != nil {
		t.Fatal(err)
	}
	x := &fakeExchanger{perAddr: map[string]func() (*dns.Msg, error){"1.1.1.1:53": okReply}}
	return startUDP(t, New(Options{
		Holder: h,
		ACL:    NewACL(allow),
		Auth: &Authoritative{
			Zone: "home.arpa.", TTL: 60,
			ReverseZones: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
		},
		Forwarder: newForwarder(x, "1.1.1.1:53"),
	}))
}

// queryFrom dials with an explicit local source address so the server's view
// matcher sees a different client each time.
func queryFrom(t *testing.T, server, source, name string, qtype uint16) *dns.Msg {
	t.Helper()
	c := &dns.Client{
		Net:     "udp",
		Timeout: 3 * time.Second,
		Dialer:  &net.Dialer{LocalAddr: &net.UDPAddr{IP: net.ParseIP(source)}},
	}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	resp, _, err := c.Exchange(m, server)
	if err != nil {
		t.Fatalf("exchange from %s: %v", source, err)
	}
	return resp
}

func allowLoopback(t *testing.T) []netip.Prefix { return prefixes(t, "127.0.0.0/8") }

// The headline behavior: one name, two source addresses, two answers.
func TestSplitHorizonOverTheWire(t *testing.T) {
	addr := newTestServer(t, allowLoopback(t))

	lan := queryFrom(t, addr, "127.0.0.2", "kypost.home.arpa.", dns.TypeA)
	if len(lan.Answer) != 1 || lan.Answer[0].(*dns.A).A.String() != "192.168.1.20" {
		t.Fatalf("lan answer = %v, want 192.168.1.20", lan.Answer)
	}
	tail := queryFrom(t, addr, "127.0.0.3", "kypost.home.arpa.", dns.TypeA)
	if len(tail.Answer) != 1 || tail.Answer[0].(*dns.A).A.String() != "100.101.102.103" {
		t.Fatalf("tailnet answer = %v, want 100.101.102.103", tail.Answer)
	}
}

func TestRefusedWhenOutsideACL(t *testing.T) {
	addr := newTestServer(t, prefixes(t, "192.168.0.0/16"))
	resp := queryFrom(t, addr, "127.0.0.2", "kypost.home.arpa.", dns.TypeA)
	if resp.Rcode != dns.RcodeRefused {
		t.Errorf("Rcode = %s, want REFUSED", dns.RcodeToString[resp.Rcode])
	}
}

func TestForwardsUnknownName(t *testing.T) {
	addr := newTestServer(t, allowLoopback(t))
	resp := queryFrom(t, addr, "127.0.0.2", "example.com.", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) == 0 {
		t.Errorf("forwarded reply = %v rcode %s", resp.Answer, dns.RcodeToString[resp.Rcode])
	}
	if resp.Authoritative {
		t.Error("AA bit set on a forwarded answer")
	}
}

func TestNXDOMAINInsideZone(t *testing.T) {
	addr := newTestServer(t, allowLoopback(t))
	resp := queryFrom(t, addr, "127.0.0.2", "nope.home.arpa.", dns.TypeA)
	if resp.Rcode != dns.RcodeNameError {
		t.Errorf("Rcode = %s, want NXDOMAIN", dns.RcodeToString[resp.Rcode])
	}
}

func TestNotImplementedForNonQueryOpcode(t *testing.T) {
	addr := newTestServer(t, allowLoopback(t))
	c := &dns.Client{Net: "udp", Timeout: 3 * time.Second}
	m := new(dns.Msg)
	m.SetQuestion("kypost.home.arpa.", dns.TypeA)
	m.Opcode = dns.OpcodeStatus
	resp, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Rcode != dns.RcodeNotImplemented {
		t.Errorf("Rcode = %s, want NOTIMP", dns.RcodeToString[resp.Rcode])
	}
}

func TestRefusedForNonINClass(t *testing.T) {
	addr := newTestServer(t, allowLoopback(t))
	c := &dns.Client{Net: "udp", Timeout: 3 * time.Second}
	m := new(dns.Msg)
	m.Id = dns.Id()
	m.RecursionDesired = true
	m.Question = []dns.Question{{Name: "kypost.home.arpa.", Qtype: dns.TypeA, Qclass: dns.ClassCHAOS}}
	resp, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Rcode != dns.RcodeRefused {
		t.Errorf("Rcode = %s, want REFUSED", dns.RcodeToString[resp.Rcode])
	}
}

func TestServfailWhenSnapshotMissingAndUpstreamsDown(t *testing.T) {
	h := zone.NewHolder(func() (zone.Input, error) { return zone.Input{Zone: "home.arpa."}, nil })
	x := &fakeExchanger{perAddr: map[string]func() (*dns.Msg, error){"1.1.1.1:53": failReply}}
	addr := startUDP(t, New(Options{
		Holder:    h, // never rebuilt: Current() is nil
		ACL:       NewACL(prefixes(t, "127.0.0.0/8")),
		Auth:      &Authoritative{Zone: "home.arpa.", TTL: 60},
		Forwarder: newForwarder(x, "1.1.1.1:53"),
	}))
	resp := queryFrom(t, addr, "127.0.0.1", "example.com.", dns.TypeA)
	if resp.Rcode != dns.RcodeServerFailure {
		t.Errorf("Rcode = %s, want SERVFAIL", dns.RcodeToString[resp.Rcode])
	}
}

// A name inside the zone is still answered authoritatively even with every
// upstream down: forwarding failures must not affect local names.
func TestAuthoritativeUnaffectedByUpstreamFailure(t *testing.T) {
	h := zone.NewHolder(func() (zone.Input, error) {
		return zone.Input{
			Zone:     "home.arpa.",
			Services: []store.Service{{ID: 1, Name: "nas", Addresses: []store.Address{{Address: "192.168.1.30"}}}},
		}, nil
	})
	if err := h.Rebuild(); err != nil {
		t.Fatal(err)
	}
	x := &fakeExchanger{perAddr: map[string]func() (*dns.Msg, error){"1.1.1.1:53": failReply}}
	addr := startUDP(t, New(Options{
		Holder:    h,
		ACL:       NewACL(prefixes(t, "127.0.0.0/8")),
		Auth:      &Authoritative{Zone: "home.arpa.", TTL: 60},
		Forwarder: newForwarder(x, "1.1.1.1:53"),
	}))
	resp := queryFrom(t, addr, "127.0.0.1", "nas.home.arpa.", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Errorf("= rcode %s answer %v, want the local answer",
			dns.RcodeToString[resp.Rcode], resp.Answer)
	}
}

func TestShutdownIsClean(t *testing.T) {
	srv := New(Options{
		Holder: zone.NewHolder(func() (zone.Input, error) { return zone.Input{Zone: "home.arpa."}, nil }),
		ACL:    NewACL(nil),
		Auth:   &Authoritative{Zone: "home.arpa.", TTL: 60},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Errorf("Shutdown() on a server that never listened = %v, want nil", err)
	}
}

// TCP must be served as well as UDP.
func TestTCPListener(t *testing.T) {
	h := zone.NewHolder(func() (zone.Input, error) {
		return zone.Input{
			Zone:     "home.arpa.",
			Services: []store.Service{{ID: 1, Name: "nas", Addresses: []store.Address{{Address: "192.168.1.30"}}}},
		}, nil
	})
	if err := h.Rebuild(); err != nil {
		t.Fatal(err)
	}
	srv := New(Options{
		Holder: h,
		ACL:    NewACL(prefixes(t, "127.0.0.0/8")),
		Auth:   &Authoritative{Zone: "home.arpa.", TTL: 60},
	})
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ds := &dns.Server{Listener: l, Handler: srv}
	go ds.ActivateAndServe()
	defer ds.Shutdown()

	c := &dns.Client{Net: "tcp", Timeout: 3 * time.Second}
	m := new(dns.Msg)
	m.SetQuestion("nas.home.arpa.", dns.TypeA)
	resp, _, err := c.Exchange(m, l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Answer) != 1 {
		t.Errorf("TCP answer = %v", resp.Answer)
	}
}

// A client that did not offer EDNS0 must not be handed an OPT record back, even
// though the forwarder always uses EDNS0 upstream.
func TestForwardedReplyHasNoOPTForAPlainClient(t *testing.T) {
	addr := newTestServer(t, allowLoopback(t))
	resp := queryFrom(t, addr, "127.0.0.1", "example.com.", dns.TypeA)
	if resp.IsEdns0() != nil {
		t.Error("reply carries an OPT record the client never asked for")
	}
}

// A client that did ask for DNSSEC records still gets an OPT record back.
func TestForwardedReplyKeepsOPTForAnEDNSClient(t *testing.T) {
	addr := newTestServer(t, allowLoopback(t))
	c := &dns.Client{
		Net:     "udp",
		Timeout: 3 * time.Second,
		Dialer:  &net.Dialer{LocalAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1")}},
	}
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	m.SetEdns0(1232, true)
	resp, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatal(err)
	}
	if resp.IsEdns0() == nil {
		t.Error("reply dropped the OPT record an EDNS0 client asked for")
	}
}

// The server must read the client's own DO bit and forward it, not hardcode
// one: hardcoding false would leave every other test green, since none of
// them check which DO value actually reached the reply. This checks a fresh
// query (a cache miss) and a repeat of the same query (a cache hit), since a
// cache that mishandled the OPT record would only show it on the second.
func TestServerReadsClientDOBit(t *testing.T) {
	for _, do := range []bool{true, false} {
		addr := newTestServer(t, allowLoopback(t))
		c := &dns.Client{
			Net:     "udp",
			Timeout: 3 * time.Second,
			Dialer:  &net.Dialer{LocalAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1")}},
		}
		for i := 0; i < 2; i++ {
			m := new(dns.Msg)
			m.SetQuestion("example.com.", dns.TypeA)
			m.SetEdns0(1232, do)
			resp, _, err := c.Exchange(m, addr)
			if err != nil {
				t.Fatal(err)
			}
			opt := resp.IsEdns0()
			if opt == nil {
				t.Fatalf("do=%t query %d: reply carries no OPT", do, i)
			}
			if opt.Do() != do {
				t.Errorf("do=%t query %d: reply DO=%t, want %t", do, i, opt.Do(), do)
			}
		}
	}
}
