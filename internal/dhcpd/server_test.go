package dhcpd

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/yoshiofthewire/kydns-server/internal/store"
)

// captureConn is the fake the handler writes replies into. No socket is
// opened anywhere in this file.
type captureConn struct {
	net.PacketConn
	mu   sync.Mutex
	sent [][]byte
}

func (c *captureConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sent = append(c.sent, append([]byte(nil), b...))
	return len(b), nil
}

func (c *captureConn) replies(t *testing.T) []*dhcpv4.DHCPv4 {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []*dhcpv4.DHCPv4
	for _, b := range c.sent {
		m, err := dhcpv4.FromBytes(b)
		if err != nil {
			t.Fatalf("reply is not a DHCP message: %v", err)
		}
		out = append(out, m)
	}
	return out
}

// memStore is an in-memory LeaseStore.
type memStore struct {
	mu sync.Mutex
	ls map[string]store.DHCPLease
}

func newMemStore() *memStore { return &memStore{ls: map[string]store.DHCPLease{}} }

func (m *memStore) DHCPLeases() ([]store.DHCPLease, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]store.DHCPLease, 0, len(m.ls))
	for _, l := range m.ls {
		out = append(out, l)
	}
	return out, nil
}

func (m *memStore) PutDHCPLease(l store.DHCPLease) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for mac, cur := range m.ls {
		if cur.IP == l.IP && mac != l.MAC {
			delete(m.ls, mac)
		}
	}
	m.ls[l.MAC] = l
	return nil
}

func (m *memStore) DeleteDHCPLease(mac string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.ls, mac)
	return nil
}

func (m *memStore) DeleteExpiredDHCPLeases(now int64) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for mac, l := range m.ls {
		if l.ExpiresAt <= now {
			delete(m.ls, mac)
			n++
		}
	}
	return n, nil
}

func newTestServer(t *testing.T) (*Server, *memStore) {
	t.Helper()
	ms := newMemStore()
	cfg := testConfig()
	s := New(Options{
		Iface:  IfaceInfo{Name: "test0", Addr: cfg.Host, Subnet: cfg.Subnet, Gateway: cfg.Gateway},
		Cfg:    cfg,
		DNS:    []netip.Addr{cfg.Host},
		Domain: "home.arpa",
		Alloc:  NewAllocator(cfg, func() time.Time { return epoch }),
		Prober: nopProber{},
		Store:  ms,
		Logger: slog.New(slog.DiscardHandler),
	})
	return s, ms
}

// newTestServerWithClock is newTestServer with a mutable clock, for tests
// that must advance time (offerHold expiry).
func newTestServerWithClock(t *testing.T) (*Server, *memStore, *time.Time) {
	t.Helper()
	ms := newMemStore()
	cfg := testConfig()
	now := epoch
	s := New(Options{
		Iface:  IfaceInfo{Name: "test0", Addr: cfg.Host, Subnet: cfg.Subnet, Gateway: cfg.Gateway},
		Cfg:    cfg,
		DNS:    []netip.Addr{cfg.Host},
		Domain: "home.arpa",
		Alloc:  NewAllocator(cfg, func() time.Time { return now }),
		Prober: nopProber{},
		Store:  ms,
		Now:    func() time.Time { return now },
		Logger: slog.New(slog.DiscardHandler),
	})
	return s, ms, &now
}

// stubProber reports exactly one address as already in use, exercising the
// probe-hit branch nopProber can never reach.
type stubProber struct{ inUse netip.Addr }

func (p stubProber) InUse(ip netip.Addr) bool { return ip == p.inUse }

func discover(mac string, hostname string) *dhcpv4.DHCPv4 {
	hw, err := net.ParseMAC(mac)
	if err != nil {
		panic(err)
	}
	m, err := dhcpv4.NewDiscovery(hw)
	if err != nil {
		panic(err)
	}
	if hostname != "" {
		m.UpdateOption(dhcpv4.OptHostName(hostname))
	}
	return m
}

func request(mac, hostname string, requested netip.Addr) *dhcpv4.DHCPv4 {
	m := discover(mac, hostname)
	m.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeRequest))
	if requested.IsValid() {
		m.UpdateOption(dhcpv4.OptRequestedIPAddress(net.IP(requested.AsSlice())))
	}
	return m
}

func TestDiscoverGetsAnOfferWithOurOptions(t *testing.T) {
	s, _ := newTestServer(t)
	c := &captureConn{}
	s.handle(c, &net.UDPAddr{IP: net.IPv4zero}, discover("aa:aa:aa:aa:aa:aa", "laptop"))

	replies := c.replies(t)
	if len(replies) != 1 {
		t.Fatalf("got %d replies to a DISCOVER, want 1", len(replies))
	}
	r := replies[0]
	if r.MessageType() != dhcpv4.MessageTypeOffer {
		t.Fatalf("message type = %v, want OFFER", r.MessageType())
	}
	if want := netip.MustParseAddr("192.168.1.10"); r.YourIPAddr.String() != want.String() {
		t.Fatalf("offered %v, want %v", r.YourIPAddr, want)
	}
	if got := r.Router(); len(got) != 1 || got[0].String() != "192.168.1.1" {
		t.Fatalf("router option = %v, want 192.168.1.1", got)
	}
	if got := r.DNS(); len(got) != 1 || got[0].String() != "192.168.1.5" {
		t.Fatalf("dns option = %v, want ourselves at 192.168.1.5", got)
	}
	if got := r.DomainName(); got != "home.arpa" {
		t.Fatalf("domain option = %q, want home.arpa", got)
	}
	if got := r.IPAddressLeaseTime(0); got != 24*time.Hour {
		t.Fatalf("lease time = %v, want 24h", got)
	}
	if got := r.ServerIdentifier(); got.String() != "192.168.1.5" {
		t.Fatalf("server identifier = %v, want 192.168.1.5", got)
	}
}

func TestDiscoverDoesNotPersistALease(t *testing.T) {
	s, ms := newTestServer(t)
	s.handle(&captureConn{}, &net.UDPAddr{IP: net.IPv4zero}, discover("aa:aa:aa:aa:aa:aa", "laptop"))
	got, _ := ms.DHCPLeases()
	if len(got) != 0 {
		t.Fatalf("a DISCOVER persisted %d leases; only a REQUEST commits", len(got))
	}
}

func TestRequestGetsAnAckAndPersists(t *testing.T) {
	s, ms := newTestServer(t)
	c := &captureConn{}
	s.handle(c, &net.UDPAddr{IP: net.IPv4zero}, request("aa:aa:aa:aa:aa:aa", "laptop", netip.Addr{}))

	replies := c.replies(t)
	if len(replies) != 1 || replies[0].MessageType() != dhcpv4.MessageTypeAck {
		t.Fatalf("replies = %+v, want one ACK", replies)
	}
	got, _ := ms.DHCPLeases()
	if len(got) != 1 {
		t.Fatalf("persisted %d leases, want 1", len(got))
	}
	if got[0].MAC != "aa:aa:aa:aa:aa:aa" || got[0].Hostname != "laptop" {
		t.Fatalf("persisted %+v, want the requesting client", got[0])
	}
}

func TestRequestForAnAddressWeDoNotControlIsNaked(t *testing.T) {
	s, _ := newTestServer(t)
	c := &captureConn{}
	// A client roaming from another network asks to keep an address that is
	// not in our subnet at all.
	s.handle(c, &net.UDPAddr{IP: net.IPv4zero},
		request("aa:aa:aa:aa:aa:aa", "laptop", netip.MustParseAddr("10.9.9.9")))

	replies := c.replies(t)
	if len(replies) != 1 || replies[0].MessageType() != dhcpv4.MessageTypeNak {
		t.Fatalf("replies = %+v, want one NAK", replies)
	}
}

func TestReleaseFreesTheAddress(t *testing.T) {
	s, ms := newTestServer(t)
	s.handle(&captureConn{}, &net.UDPAddr{IP: net.IPv4zero}, request("aa:aa:aa:aa:aa:aa", "laptop", netip.Addr{}))

	rel := discover("aa:aa:aa:aa:aa:aa", "laptop")
	rel.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeRelease))
	c := &captureConn{}
	s.handle(c, &net.UDPAddr{IP: net.IPv4zero}, rel)

	if n := len(c.replies(t)); n != 0 {
		t.Fatalf("RELEASE drew %d replies, want none", n)
	}
	got, _ := ms.DHCPLeases()
	if len(got) != 0 {
		t.Fatalf("leases after RELEASE = %+v, want none", got)
	}
}

func TestDeclineQuarantinesTheAddress(t *testing.T) {
	s, _ := newTestServer(t)
	c := &captureConn{}
	s.handle(c, &net.UDPAddr{IP: net.IPv4zero}, request("aa:aa:aa:aa:aa:aa", "one", netip.Addr{}))
	first := c.replies(t)[0].YourIPAddr

	dec := discover("aa:aa:aa:aa:aa:aa", "one")
	dec.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeDecline))
	dec.UpdateOption(dhcpv4.OptRequestedIPAddress(first))
	s.handle(&captureConn{}, &net.UDPAddr{IP: net.IPv4zero}, dec)

	c2 := &captureConn{}
	s.handle(c2, &net.UDPAddr{IP: net.IPv4zero}, request("bb:bb:bb:bb:bb:bb", "two", netip.Addr{}))
	if got := c2.replies(t)[0].YourIPAddr; got.Equal(first) {
		t.Fatalf("re-offered %v after it was declined", got)
	}
}

func TestInformGetsOptionsAndNoAddress(t *testing.T) {
	s, ms := newTestServer(t)
	inf := discover("aa:aa:aa:aa:aa:aa", "laptop")
	inf.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeInform))
	c := &captureConn{}
	s.handle(c, &net.UDPAddr{IP: net.IPv4zero}, inf)

	replies := c.replies(t)
	if len(replies) != 1 || replies[0].MessageType() != dhcpv4.MessageTypeAck {
		t.Fatalf("replies = %+v, want one ACK", replies)
	}
	if !replies[0].YourIPAddr.Equal(net.IPv4zero) {
		t.Fatalf("INFORM reply carried address %v, want none", replies[0].YourIPAddr)
	}
	if got, _ := ms.DHCPLeases(); len(got) != 0 {
		t.Fatalf("INFORM persisted %d leases, want 0", len(got))
	}
}

func TestSecondClaimOnAHostnameGetsNoName(t *testing.T) {
	s, ms := newTestServer(t)
	s.handle(&captureConn{}, &net.UDPAddr{IP: net.IPv4zero}, request("aa:aa:aa:aa:aa:aa", "laptop", netip.Addr{}))
	s.handle(&captureConn{}, &net.UDPAddr{IP: net.IPv4zero}, request("bb:bb:bb:bb:bb:bb", "laptop", netip.Addr{}))

	got, _ := ms.DHCPLeases()
	if len(got) != 2 {
		t.Fatalf("persisted %d leases, want 2: the second client still gets an address", len(got))
	}
	named := 0
	for _, l := range got {
		if l.Hostname == "laptop" {
			named++
		}
	}
	if named != 1 {
		t.Fatalf("%d leases claim the name laptop, want exactly 1", named)
	}
}

func TestLeasesImplementsTheDiscoverySource(t *testing.T) {
	s, _ := newTestServer(t)
	s.handle(&captureConn{}, &net.UDPAddr{IP: net.IPv4zero}, request("aa:aa:aa:aa:aa:aa", "laptop", netip.Addr{}))

	ls, err := s.Leases(t.Context())
	if err != nil {
		t.Fatalf("Leases: %v", err)
	}
	if len(ls) != 1 {
		t.Fatalf("Leases returned %d, want 1", len(ls))
	}
	if ls[0].Hostname != "laptop" || ls[0].IP != "192.168.1.10" {
		t.Fatalf("lease = %+v, want laptop at 192.168.1.10", ls[0])
	}
	if s.Name() == "" {
		t.Fatal("Name is empty; it appears in logs and the UI")
	}
}

func TestMalformedPacketsAreDroppedNotFatal(t *testing.T) {
	s, _ := newTestServer(t)
	c := &captureConn{}
	// No message type option at all.
	m, err := dhcpv4.New()
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	s.handle(c, &net.UDPAddr{IP: net.IPv4zero}, m)
	if n := len(c.replies(t)); n != 0 {
		t.Fatalf("a message with no type drew %d replies, want none", n)
	}
}

func TestSanitizeHostname(t *testing.T) {
	cases := []struct{ in, want string }{
		{"laptop", "laptop"},
		{"LAPTOP", "laptop"},
		{"  laptop  ", "laptop"},
		{"laptop.lan", "laptop"},
		{"my-laptop-2", "my-laptop-2"},
		{"", ""},
		{"-leading", ""},
		{"trailing-", ""},
		{"has space", ""},
		{"has_underscore", ""},
		{"inject\x00null", ""},
		{"wildcard*", ""},
		{strings.Repeat("a", 64), ""},
		{strings.Repeat("a", 63), strings.Repeat("a", 63)},
	}
	for _, c := range cases {
		if got := sanitizeHostname(c.in); got != c.want {
			t.Fatalf("sanitizeHostname(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestDiscoverNeverAppearsInLeases(t *testing.T) {
	s, _ := newTestServer(t)
	s.handle(&captureConn{}, &net.UDPAddr{IP: net.IPv4zero}, discover("aa:aa:aa:aa:aa:aa", "laptop"))

	ls, err := s.Leases(t.Context())
	if err != nil {
		t.Fatalf("Leases: %v", err)
	}
	if len(ls) != 0 {
		t.Fatalf("Leases returned %d after a bare DISCOVER, want 0: an offer is a hold, not a lease", len(ls))
	}
}

func TestDiscoverHoldExpiresAndAddressBecomesAllocatable(t *testing.T) {
	s, _, now := newTestServerWithClock(t)
	c := &captureConn{}
	s.handle(c, &net.UDPAddr{IP: net.IPv4zero}, discover("aa:aa:aa:aa:aa:aa", "laptop"))
	first := c.replies(t)[0].YourIPAddr

	*now = now.Add(offerHold + time.Second)

	c2 := &captureConn{}
	s.handle(c2, &net.UDPAddr{IP: net.IPv4zero}, discover("bb:bb:bb:bb:bb:bb", "other"))
	second := c2.replies(t)[0].YourIPAddr
	if !second.Equal(first) {
		t.Fatalf("offer after the hold expired = %v, want the expired hold %v reused", second, first)
	}
}

func TestDiscoverHostnameIsNotClaimed(t *testing.T) {
	s, ms := newTestServer(t)
	s.handle(&captureConn{}, &net.UDPAddr{IP: net.IPv4zero}, discover("aa:aa:aa:aa:aa:aa", "laptop"))

	c := &captureConn{}
	s.handle(c, &net.UDPAddr{IP: net.IPv4zero}, request("bb:bb:bb:bb:bb:bb", "laptop", netip.Addr{}))
	if got := c.replies(t)[0].MessageType(); got != dhcpv4.MessageTypeAck {
		t.Fatalf("second client's REQUEST for the name got %v, want ACK", got)
	}
	got, _ := ms.DHCPLeases()
	if len(got) != 1 || got[0].Hostname != "laptop" || got[0].MAC != "bb:bb:bb:bb:bb:bb" {
		t.Fatalf("leases = %+v, want the REQUESTing client alone to hold the name laptop", got)
	}
}

func TestAckGrantsTheFullLeaseTerm(t *testing.T) {
	s, ms := newTestServer(t)
	s.handle(&captureConn{}, &net.UDPAddr{IP: net.IPv4zero}, request("aa:aa:aa:aa:aa:aa", "laptop", netip.Addr{}))

	got, _ := ms.DHCPLeases()
	if len(got) != 1 {
		t.Fatalf("persisted %d leases, want 1", len(got))
	}
	if want := epoch.Add(24 * time.Hour).Unix(); got[0].ExpiresAt != want {
		t.Fatalf("ExpiresAt = %d, want %d: an ACK grants the full configured lease term", got[0].ExpiresAt, want)
	}
}

func TestProbeHitSkipsToTheNextAddressAndQuarantines(t *testing.T) {
	s, _ := newTestServer(t)
	hit := netip.MustParseAddr("192.168.1.10")
	s.opts.Prober = stubProber{inUse: hit}

	c := &captureConn{}
	s.handle(c, &net.UDPAddr{IP: net.IPv4zero}, discover("aa:aa:aa:aa:aa:aa", "laptop"))
	replies := c.replies(t)
	if len(replies) != 1 {
		t.Fatalf("got %d replies, want 1", len(replies))
	}
	if got := replies[0].YourIPAddr; got.Equal(net.IP(hit.AsSlice())) {
		t.Fatalf("offered %v, the address the probe reported in use", got)
	}

	// The probed address must be quarantined, not merely skipped this once.
	l, _ := s.opts.Alloc.Allocate("cc:cc:cc:cc:cc:cc", "", hit, time.Hour)
	if l.IP == hit {
		t.Fatalf("Allocate handed out %v after the probe quarantined it", hit)
	}
}

func TestProbeHitWithNoFallbackAddressDrawsNoReply(t *testing.T) {
	ms := newMemStore()
	cfg := testConfig()
	cfg.End = cfg.Start // a single-address pool
	s := New(Options{
		Iface:  IfaceInfo{Name: "test0", Addr: cfg.Host, Subnet: cfg.Subnet, Gateway: cfg.Gateway},
		Cfg:    cfg,
		Alloc:  NewAllocator(cfg, func() time.Time { return epoch }),
		Prober: stubProber{inUse: cfg.Start},
		Store:  ms,
		Logger: slog.New(slog.DiscardHandler),
	})

	c := &captureConn{}
	s.handle(c, &net.UDPAddr{IP: net.IPv4zero}, discover("aa:aa:aa:aa:aa:aa", "laptop"))
	if n := len(c.replies(t)); n != 0 {
		t.Fatalf("got %d replies for a one-address pool whose only address failed the probe, want 0", n)
	}
}

func TestNormalizeMAC(t *testing.T) {
	cases := []struct{ in, want string }{
		{"AA:BB:CC:DD:EE:FF", "aa:bb:cc:dd:ee:ff"},
		{"aa-bb-cc-dd-ee-ff", "aa:bb:cc:dd:ee:ff"},
		{"aabb.ccdd.eeff", "aa:bb:cc:dd:ee:ff"},
		{"  aa:bb:cc:dd:ee:ff  ", "aa:bb:cc:dd:ee:ff"},
		{"a:b:c:d:e:f", "a:b:c:d:e:f"}, // does not parse; falls back lowercased
		{"not-a-mac", "not-a-mac"},
		{"", ""},
	}
	for _, c := range cases {
		if got := normalizeMAC(c.in); got != c.want {
			t.Fatalf("normalizeMAC(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestStopCancelsAndIsIdempotent drives Stop directly, without Start, so it
// never binds a socket. It pins the two things Start/Stop must get right:
// Stop cancels the run context (so the watcher goroutine started by Start
// can exit, and Serve's error after Close is recognized as intentional), and
// a second Stop -- called both by an admin action and by that same watcher
// goroutine -- is a no-op rather than a double-cancel or a panic.
func TestStopCancelsAndIsIdempotent(t *testing.T) {
	s, _ := newTestServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	called := false
	s.mu.Lock()
	s.cancel = func() { called = true; cancel() }
	s.mu.Unlock()

	if err := s.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if !called {
		t.Fatal("Stop did not call cancel")
	}
	if ctx.Err() == nil {
		t.Fatal("Stop's cancel had no effect on the run context")
	}

	if err := s.Stop(); err != nil {
		t.Fatalf("second Stop: %v", err)
	}
}
