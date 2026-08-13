package dnsserver

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"strings"
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
	}, nil)
	if err := h.Rebuild(); err != nil {
		t.Fatal(err)
	}
	return startUDP(t, New(Options{
		Holder:    h,
		ACL:       NewACL(allow),
		Auth:      NewAuthoritative("home.arpa.", 60, []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}),
		Forwarder: newForwarder(okUpstream("tls://1.1.1.1:853", true)),
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
	h := zone.NewHolder(func() (zone.Input, error) { return zone.Input{Zone: "home.arpa."}, nil }, nil)
	addr := startUDP(t, New(Options{
		Holder:    h, // never rebuilt: Current() is nil
		ACL:       NewACL(prefixes(t, "127.0.0.0/8")),
		Auth:      NewAuthoritative("home.arpa.", 60, nil),
		Forwarder: newForwarder(deadUpstream("tls://1.1.1.1:853", true)),
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
	}, nil)
	if err := h.Rebuild(); err != nil {
		t.Fatal(err)
	}
	addr := startUDP(t, New(Options{
		Holder:    h,
		ACL:       NewACL(prefixes(t, "127.0.0.0/8")),
		Auth:      NewAuthoritative("home.arpa.", 60, nil),
		Forwarder: newForwarder(deadUpstream("tls://1.1.1.1:853", true)),
	}))
	resp := queryFrom(t, addr, "127.0.0.1", "nas.home.arpa.", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Errorf("= rcode %s answer %v, want the local answer",
			dns.RcodeToString[resp.Rcode], resp.Answer)
	}
}

func TestShutdownIsClean(t *testing.T) {
	srv := New(Options{
		Holder: zone.NewHolder(func() (zone.Input, error) { return zone.Input{Zone: "home.arpa."}, nil }, nil),
		ACL:    NewACL(nil),
		Auth:   NewAuthoritative("home.arpa.", 60, nil),
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
	}, nil)
	if err := h.Rebuild(); err != nil {
		t.Fatal(err)
	}
	srv := New(Options{
		Holder: h,
		ACL:    NewACL(prefixes(t, "127.0.0.0/8")),
		Auth:   NewAuthoritative("home.arpa.", 60, nil),
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

// forwardOnlyServer holds an empty zone, so every query reaches u.
func forwardOnlyServer(t *testing.T, u *fakeUpstream) string {
	t.Helper()
	h := zone.NewHolder(func() (zone.Input, error) { return zone.Input{Zone: "home.arpa."}, nil }, nil)
	if err := h.Rebuild(); err != nil {
		t.Fatal(err)
	}
	return startUDP(t, New(Options{
		Holder:    h,
		ACL:       NewACL(prefixes(t, "127.0.0.0/8")),
		Auth:      NewAuthoritative("home.arpa.", 60, nil),
		Forwarder: newForwarder(u),
	}))
}

// udpExchange sends one datagram and returns the parsed reply plus the byte
// count that actually crossed the wire. The read buffer is deliberately larger
// than any advertised size, so the count measures the server, not the client.
func udpExchange(t *testing.T, server string, m *dns.Msg) (*dns.Msg, int) {
	t.Helper()
	wire, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("udp", server)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(wire); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, dns.MaxMsgSize)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	resp := new(dns.Msg)
	if err := resp.Unpack(buf[:n]); err != nil {
		t.Fatalf("reply of %d bytes does not parse: %v", n, err)
	}
	return resp, n
}

// A UDP reply larger than the client advertised is chopped by the kernel, and
// with TC clear the stub has no signal to retry over TCP. Forwarding the DO
// bit made over-large answers routine, so this has to hold for every client
// class.
func TestUDPReplyRespectsTheClientsBufferSize(t *testing.T) {
	t.Run("edns client gets TC and a reply within its budget", func(t *testing.T) {
		addr := forwardOnlyServer(t, bigUpstream("tls://1.1.1.1:853", true))
		m := new(dns.Msg)
		m.SetQuestion("big.example.com.", dns.TypeTXT)
		m.SetEdns0(1232, true)
		resp, n := udpExchange(t, addr, m)
		if n > 1232 {
			t.Errorf("reply = %d bytes to a client advertising 1232", n)
		}
		if !resp.Truncated {
			t.Error("TC clear on a shortened reply: nothing tells the client to retry over TCP")
		}
	})

	t.Run("a big enough client gets the whole answer", func(t *testing.T) {
		addr := forwardOnlyServer(t, bigUpstream("tls://1.1.1.1:853", true))
		m := new(dns.Msg)
		m.SetQuestion("big.example.com.", dns.TypeTXT)
		m.SetEdns0(4096, true)
		resp, n := udpExchange(t, addr, m)
		if n <= 1232 {
			t.Errorf("reply = %d bytes, want the full answer a 4096 client can hold", n)
		}
		if resp.Truncated {
			t.Error("TC set on a reply that fits")
		}
		if len(resp.Answer) != 10 {
			t.Errorf("Answer = %d records, want all 10", len(resp.Answer))
		}
	})

	t.Run("a non-EDNS client is held to 512", func(t *testing.T) {
		addr := forwardOnlyServer(t, bigUpstream("tls://1.1.1.1:853", true))
		m := new(dns.Msg)
		m.SetQuestion("big.example.com.", dns.TypeTXT)
		resp, n := udpExchange(t, addr, m)
		if n > dns.MinMsgSize {
			t.Errorf("reply = %d bytes to a client that never offered EDNS0", n)
		}
		if !resp.Truncated {
			t.Error("TC clear on a shortened reply to a non-EDNS client")
		}
		if resp.IsEdns0() != nil {
			t.Error("reply carries an OPT record the client never asked for")
		}
	})
}

// TCP has no datagram ceiling, so the same over-large answer must arrive whole.
func TestTCPReplyIsNotTruncated(t *testing.T) {
	h := zone.NewHolder(func() (zone.Input, error) { return zone.Input{Zone: "home.arpa."}, nil }, nil)
	if err := h.Rebuild(); err != nil {
		t.Fatal(err)
	}
	srv := New(Options{
		Holder:    h,
		ACL:       NewACL(prefixes(t, "127.0.0.0/8")),
		Auth:      NewAuthoritative("home.arpa.", 60, nil),
		Forwarder: newForwarder(bigUpstream("tls://1.1.1.1:853", true)),
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
	m.SetQuestion("big.example.com.", dns.TypeTXT)
	m.SetEdns0(1232, true)
	resp, _, err := c.Exchange(m, l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if resp.Truncated || len(resp.Answer) != 10 {
		t.Errorf("TCP reply: TC=%t answers=%d, want the whole answer", resp.Truncated, len(resp.Answer))
	}
}

// Authoritative answers are unsigned local data. Nothing validated them, so
// they must never claim to be authenticated.
func TestAuthoritativeAnswerNeverCarriesAD(t *testing.T) {
	addr := newTestServer(t, allowLoopback(t))
	for _, name := range []string{"kypost.home.arpa.", "20.1.168.192.in-addr.arpa."} {
		qtype := dns.TypeA
		if name != "kypost.home.arpa." {
			qtype = dns.TypePTR
		}
		resp := queryFrom(t, addr, "127.0.0.2", name, qtype)
		if resp.AuthenticatedData {
			t.Errorf("%s: AD = true on an unsigned local answer", name)
		}
	}
}

// fakeResponseWriter drives ServeDNS synchronously with a fixed client
// address, so the caller can inspect logger output right after the call
// returns without racing the goroutine a real listener would use.
type fakeResponseWriter struct {
	remote   net.Addr
	msg      *dns.Msg
	writeErr error // returned from WriteMsg instead of storing msg, to simulate a write failure
}

func (f *fakeResponseWriter) LocalAddr() net.Addr  { return &net.UDPAddr{IP: net.ParseIP("127.0.0.1")} }
func (f *fakeResponseWriter) RemoteAddr() net.Addr { return f.remote }
func (f *fakeResponseWriter) WriteMsg(m *dns.Msg) error {
	if f.writeErr != nil {
		return f.writeErr
	}
	f.msg = m
	return nil
}
func (f *fakeResponseWriter) Write(b []byte) (int, error) { return len(b), nil }
func (f *fakeResponseWriter) Close() error                { return nil }
func (f *fakeResponseWriter) TsigStatus() error           { return nil }
func (f *fakeResponseWriter) TsigTimersOnly(bool)         {}
func (f *fakeResponseWriter) Hijack()                     {}

// query drives one A query through ServeDNS from source, synchronously.
func (s *Server) query(t *testing.T, name, source string) {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	w := &fakeResponseWriter{remote: &net.UDPAddr{IP: net.ParseIP(source), Port: 12345}}
	s.ServeDNS(w, m)
}

// The two logging opt-ins must stay independent: turning on query logging
// must never start recording client IPs on its own.
func TestSetLogging(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	h := zone.NewHolder(func() (zone.Input, error) {
		return zone.Input{
			Zone:     "home.arpa.",
			Services: []store.Service{{ID: 1, Name: "nas", Addresses: []store.Address{{Address: "192.168.1.30"}}}},
		}, nil
	}, nil)
	if err := h.Rebuild(); err != nil {
		t.Fatal(err)
	}
	s := New(Options{
		Holder: h,
		ACL:    NewACL(prefixes(t, "0.0.0.0/0")),
		Auth:   NewAuthoritative("home.arpa.", 60, nil),
		Logger: logger,
	})

	s.query(t, "nas.home.arpa.", "192.168.1.5")
	if buf.Len() != 0 {
		t.Fatal("a query was logged while query logging is off")
	}

	s.SetLogging(true, false)
	s.query(t, "nas.home.arpa.", "192.168.1.5")
	out := buf.String()
	if out == "" {
		t.Fatal("query logging was turned on but nothing was logged")
	}
	if strings.Contains(out, "192.168.1.5") {
		t.Error("the client IP was logged with log_client_ip off")
	}

	buf.Reset()
	s.SetLogging(true, true)
	s.query(t, "nas.home.arpa.", "192.168.1.5")
	if !strings.Contains(buf.String(), "192.168.1.5") {
		t.Error("the client IP was not logged with log_client_ip on")
	}
}

// A WriteMsg failure (EMSGSIZE, an ICMP-induced connection error, a
// mid-reply TCP hangup) is logged unconditionally, unlike the query log
// line — that path is not gated by log_queries or log_client_ip. A
// *net.OpError's Error() embeds the peer address, so this path must not be
// allowed to leak the client IP when log_client_ip is off; LOGGING.md
// promises no client IP is logged by default.
func TestWriteErrorNeverLeaksClientIPWhenOff(t *testing.T) {
	h := zone.NewHolder(func() (zone.Input, error) { return zone.Input{Zone: "home.arpa."}, nil }, nil)
	if err := h.Rebuild(); err != nil {
		t.Fatal(err)
	}
	newSrv := func(buf *bytes.Buffer) *Server {
		return New(Options{
			Holder: h,
			ACL:    NewACL(prefixes(t, "0.0.0.0/0")),
			Auth:   NewAuthoritative("home.arpa.", 60, nil),
			Logger: slog.New(slog.NewTextHandler(buf, nil)),
		})
	}
	writeErr := &net.OpError{
		Op:   "write",
		Net:  "udp4",
		Addr: &net.UDPAddr{IP: net.ParseIP("192.168.1.5"), Port: 12345},
		Err:  errors.New("sendmsg: message too long"),
	}
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)

	var buf bytes.Buffer
	srv := newSrv(&buf)
	w := &fakeResponseWriter{remote: &net.UDPAddr{IP: net.ParseIP("192.168.1.5"), Port: 12345}, writeErr: writeErr}
	srv.ServeDNS(w, m)

	out := buf.String()
	if out == "" {
		t.Fatal("a write failure was not logged at all")
	}
	if strings.Contains(out, "192.168.1.5") {
		t.Error("the write-error log line leaked the client IP with log_client_ip off")
	}
	if !strings.Contains(out, "sendmsg: message too long") {
		t.Errorf("write-error log line = %q, want it to still describe the failure", out)
	}

	// With log_client_ip on, the address is expected: that flag means the
	// operator opted in to seeing it.
	buf.Reset()
	srv2 := newSrv(&buf)
	srv2.SetLogging(false, true)
	w2 := &fakeResponseWriter{remote: &net.UDPAddr{IP: net.ParseIP("192.168.1.5"), Port: 12345}, writeErr: writeErr}
	srv2.ServeDNS(w2, m)
	if !strings.Contains(buf.String(), "192.168.1.5") {
		t.Error("the write-error log line dropped the client IP with log_client_ip on")
	}
}
