package dhcpd

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"net/netip"
	"slices"
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
	// dels counts delete calls, including the ones that match no row: an
	// unauthenticated packet reaching the store at all is the finding.
	dels int
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
	m.dels++
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
		// One clock for the whole harness: with Server.now left on the wall
		// clock, restore() prunes every epoch-dated row as expired.
		Now:    func() time.Time { return epoch },
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

// anonymous builds a packet with no chaddr and drives it through the real
// parse path, because that is the only place hlen=0 exists: serialized and
// re-parsed is exactly what server4.Serve hands the handler, and it does no
// chaddr validation of its own.
func anonymous(t *testing.T, mt dhcpv4.MessageType, requested netip.Addr) *dhcpv4.DHCPv4 {
	t.Helper()
	m, err := dhcpv4.New()
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	m.OpCode = dhcpv4.OpcodeBootRequest
	m.ClientHWAddr = nil
	m.UpdateOption(dhcpv4.OptMessageType(mt))
	if requested.IsValid() {
		m.UpdateOption(dhcpv4.OptRequestedIPAddress(net.IP(requested.AsSlice())))
	}
	on, err := dhcpv4.FromBytes(m.ToBytes())
	if err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	if on.ClientHWAddr.String() != "" {
		t.Fatalf("the packet carries MAC %q; this test needs one with none", on.ClientHWAddr)
	}
	return on
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
		Now:    func() time.Time { return epoch },
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

// A DISCOVER is not a lease operation, so it must not cut a lease's life.
// Anyone on the segment can broadcast one carrying a victim's MAC and no
// option 12; the lease it already holds has to survive it intact.
func TestDiscoverDoesNotWeakenAnExistingLease(t *testing.T) {
	s, ms := newTestServer(t)
	s.handle(&captureConn{}, &net.UDPAddr{IP: net.IPv4zero}, request("aa:aa:aa:aa:aa:aa", "laptop", netip.Addr{}))
	before, _ := ms.DHCPLeases()
	if len(before) != 1 || before[0].Hostname != "laptop" {
		t.Fatalf("setup: persisted %+v, want one laptop lease", before)
	}

	s.handle(&captureConn{}, &net.UDPAddr{IP: net.IPv4zero}, discover("aa:aa:aa:aa:aa:aa", ""))

	ls, err := s.Leases(t.Context())
	if err != nil {
		t.Fatalf("Leases: %v", err)
	}
	if len(ls) != 1 {
		t.Fatalf("Leases returned %d after a bare DISCOVER from the holder, want 1", len(ls))
	}
	if ls[0].Hostname != "laptop" || ls[0].IP != before[0].IP {
		t.Fatalf("lease = %+v, want laptop still at %s", ls[0], before[0].IP)
	}
	if want := time.Unix(before[0].ExpiresAt, 0); !ls[0].Expires.Equal(want) {
		t.Fatalf("expiry = %v, want %v: an offer must not move a lease's expiry earlier", ls[0].Expires, want)
	}
	got, _ := ms.DHCPLeases()
	if len(got) != 1 || got[0] != before[0] {
		t.Fatalf("stored lease = %+v, want %+v untouched", got, before[0])
	}
}

// The same DISCOVER must not free the victim's address either: an offer hold
// that expires under a live lease hands that address to a second client while
// the first is still using it.
func TestDiscoverDoesNotFreeAnExistingLeaseForAnotherClient(t *testing.T) {
	s, _, now := newTestServerWithClock(t)
	c := &captureConn{}
	s.handle(c, &net.UDPAddr{IP: net.IPv4zero}, request("aa:aa:aa:aa:aa:aa", "laptop", netip.Addr{}))
	victim := c.replies(t)[0].YourIPAddr
	// Not prober-blind: the victim answers a probe of its own address.
	s.opts.Prober = stubProber{inUse: netip.MustParseAddr(victim.String())}

	s.handle(&captureConn{}, &net.UDPAddr{IP: net.IPv4zero}, discover("aa:aa:aa:aa:aa:aa", ""))
	*now = now.Add(offerHold + time.Second)

	c2 := &captureConn{}
	s.handle(c2, &net.UDPAddr{IP: net.IPv4zero}, request("bb:bb:bb:bb:bb:bb", "other", netip.Addr{}))
	if got := c2.replies(t)[0].YourIPAddr; got.Equal(victim) {
		t.Fatalf("acked %v to a second client while the first still holds it", got)
	}
	ls, _ := s.Leases(t.Context())
	held := false
	for _, l := range ls {
		if l.MAC == "aa:aa:aa:aa:aa:aa" && l.IP == victim.String() && l.Hostname == "laptop" {
			held = true
		}
	}
	if !held {
		t.Fatalf("leases = %+v, want the first client still holding laptop at %v", ls, victim)
	}
}

// Rule 1 reaches the same commit as rule 2: a reserved client that already
// holds its reserved address must not be stripped by a bare DISCOVER either.
func TestDiscoverDoesNotWeakenAReservedClientsLease(t *testing.T) {
	s, _ := newTestServer(t)
	const mac = "aa:aa:aa:aa:aa:aa"
	res := netip.MustParseAddr("192.168.1.11")
	s.opts.Alloc.SetReservations(map[string]netip.Addr{mac: res})

	s.handle(&captureConn{}, &net.UDPAddr{IP: net.IPv4zero}, request(mac, "laptop", netip.Addr{}))
	s.handle(&captureConn{}, &net.UDPAddr{IP: net.IPv4zero}, discover(mac, ""))

	ls, _ := s.Leases(t.Context())
	if len(ls) != 1 {
		t.Fatalf("Leases returned %d after a bare DISCOVER from the reserved client, want 1", len(ls))
	}
	if ls[0].IP != res.String() || ls[0].Hostname != "laptop" {
		t.Fatalf("lease = %+v, want laptop at the reserved %v", ls[0], res)
	}
	if want := epoch.Add(24 * time.Hour); !ls[0].Expires.Equal(want) {
		t.Fatalf("expiry = %v, want the full term %v", ls[0].Expires, want)
	}
}

// The guard belongs to the offer path only. A REQUEST is a lease operation,
// and a device that sends no hostname gets no name.
func TestRequestWithNoHostnameClearsTheName(t *testing.T) {
	s, ms := newTestServer(t)
	s.handle(&captureConn{}, &net.UDPAddr{IP: net.IPv4zero}, request("aa:aa:aa:aa:aa:aa", "laptop", netip.Addr{}))
	s.handle(&captureConn{}, &net.UDPAddr{IP: net.IPv4zero}, request("aa:aa:aa:aa:aa:aa", "", netip.Addr{}))

	got, _ := ms.DHCPLeases()
	if len(got) != 1 || got[0].Hostname != "" {
		t.Fatalf("persisted %+v, want one lease with no name", got)
	}
	if ls, _ := s.Leases(t.Context()); len(ls) != 0 {
		t.Fatalf("Leases returned %+v, want none: a client that sends no hostname gets no name", ls)
	}
}

// A client's own ARP answer is not a conflict. Probing an address the client
// already holds would quarantine its lease and push it onto a new one, so the
// probe runs only for an address that is new to it.
func TestDiscoverDoesNotProbeAnAddressTheClientAlreadyHolds(t *testing.T) {
	s, ms := newTestServer(t)
	const mac = "aa:aa:aa:aa:aa:aa"
	s.handle(&captureConn{}, &net.UDPAddr{IP: net.IPv4zero}, request(mac, "laptop", netip.Addr{}))
	before, _ := ms.DHCPLeases()
	if len(before) != 1 {
		t.Fatalf("setup: persisted %+v, want one laptop lease", before)
	}
	held := netip.MustParseAddr(before[0].IP)
	s.opts.Prober = stubProber{inUse: held}

	c := &captureConn{}
	s.handle(c, &net.UDPAddr{IP: net.IPv4zero}, discover(mac, ""))

	replies := c.replies(t)
	if len(replies) != 1 {
		t.Fatalf("got %d replies to a DISCOVER, want 1", len(replies))
	}
	if got := replies[0].YourIPAddr; got.String() != held.String() {
		t.Fatalf("offered %v, want the address the client already holds, %v", got, held)
	}
	ls, _ := s.Leases(t.Context())
	if len(ls) != 1 || ls[0].Hostname != "laptop" || ls[0].IP != held.String() {
		t.Fatalf("leases = %+v, want laptop still at %v", ls, held)
	}
	if want := epoch.Add(24 * time.Hour); !ls[0].Expires.Equal(want) {
		t.Fatalf("expiry = %v, want the full term %v", ls[0].Expires, want)
	}
}

// The reservation variant: rule 1 is not a new address either, and
// quarantining a reservation would strand the client off it for 10 minutes.
func TestDiscoverDoesNotProbeAReservedClientsAddress(t *testing.T) {
	s, _ := newTestServer(t)
	const mac = "aa:aa:aa:aa:aa:aa"
	res := netip.MustParseAddr("192.168.1.11")
	s.opts.Alloc.SetReservations(map[string]netip.Addr{mac: res})
	s.handle(&captureConn{}, &net.UDPAddr{IP: net.IPv4zero}, request(mac, "laptop", netip.Addr{}))
	s.opts.Prober = stubProber{inUse: res}

	s.handle(&captureConn{}, &net.UDPAddr{IP: net.IPv4zero}, discover(mac, ""))

	ls, _ := s.Leases(t.Context())
	if len(ls) != 1 || ls[0].IP != res.String() || ls[0].Hostname != "laptop" {
		t.Fatalf("leases = %+v, want laptop still at the reserved %v", ls, res)
	}
	if want := epoch.Add(24 * time.Hour); !ls[0].Expires.Equal(want) {
		t.Fatalf("expiry = %v, want the full term %v", ls[0].Expires, want)
	}
	if _, ok := s.opts.Alloc.quarantine[res]; ok {
		t.Fatalf("%v was quarantined by its own holder answering the probe", res)
	}
}

// Round 3 made rule 2 (renew what this client already holds) skip the probe
// unconditionally. There is no reaper, so a departed client's byMAC entry
// outlives its lease: once expired, that holding is no longer this client's
// to reclaim unprobed, and something else may have taken it since.
func TestDiscoverProbesAnExpiredHoldingsAddress(t *testing.T) {
	s, _, now := newTestServerWithClock(t)
	c := &captureConn{}
	s.handle(c, &net.UDPAddr{IP: net.IPv4zero}, request("aa:aa:aa:aa:aa:aa", "laptop", netip.Addr{}))
	held := c.replies(t)[0].YourIPAddr

	*now = now.Add(24*time.Hour + time.Second) // past the lease's Expires
	s.opts.Prober = stubProber{inUse: netip.MustParseAddr(held.String())}

	c2 := &captureConn{}
	s.handle(c2, &net.UDPAddr{IP: net.IPv4zero}, discover("aa:aa:aa:aa:aa:aa", ""))
	replies := c2.replies(t)
	if len(replies) != 1 {
		t.Fatalf("got %d replies, want 1", len(replies))
	}
	if got := replies[0].YourIPAddr; got.Equal(held) {
		t.Fatalf("offered %v, the expired holding a static device now answers a probe for", got)
	}
}

// Both existing probe tests drive a bare DISCOVER with no option 50, so they
// exercise rule 4 (lowest free) only. This covers rule 3: a requested address
// that the prober reports in use must be probed and skipped too.
func TestProbeHitOnARequestedAddressSkipsAndQuarantines(t *testing.T) {
	s, _ := newTestServer(t)
	requested := netip.MustParseAddr("192.168.1.11")
	s.opts.Prober = stubProber{inUse: requested}

	d := discover("aa:aa:aa:aa:aa:aa", "laptop")
	d.UpdateOption(dhcpv4.OptRequestedIPAddress(net.IP(requested.AsSlice())))
	c := &captureConn{}
	s.handle(c, &net.UDPAddr{IP: net.IPv4zero}, d)

	replies := c.replies(t)
	if len(replies) != 1 {
		t.Fatalf("got %d replies, want 1", len(replies))
	}
	if got := replies[0].YourIPAddr; got.Equal(net.IP(requested.AsSlice())) {
		t.Fatalf("offered %v, the requested address the probe reported in use", got)
	}

	// The probed address must be quarantined, not merely skipped this once.
	l, _ := s.opts.Alloc.Allocate("cc:cc:cc:cc:cc:cc", "", requested, time.Hour)
	if l.IP == requested {
		t.Fatalf("Allocate handed out %v after the probe quarantined it", requested)
	}
}

// A DECLINE is an unauthenticated broadcast. The only thing that makes it
// credible is that the sender holds the address it is declining, so a decline
// naming somebody else's address must change nothing at all.
func TestDeclineFromAnotherClientLeavesTheLeaseAlone(t *testing.T) {
	s, ms := newTestServer(t)
	c := &captureConn{}
	s.handle(c, &net.UDPAddr{IP: net.IPv4zero}, request("aa:aa:aa:aa:aa:aa", "nas", netip.Addr{}))
	victim := c.replies(t)[0].YourIPAddr

	dec := discover("bb:bb:bb:bb:bb:bb", "")
	dec.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeDecline))
	dec.UpdateOption(dhcpv4.OptRequestedIPAddress(victim))
	s.handle(&captureConn{}, &net.UDPAddr{IP: net.IPv4zero}, dec)

	ls, err := s.Leases(context.Background())
	if err != nil {
		t.Fatalf("Leases: %v", err)
	}
	if len(ls) != 1 || ls[0].Hostname != "nas" || ls[0].IP != victim.String() {
		t.Fatalf("leases after a spoofed decline = %+v, want nas still holding %v", ls, victim)
	}
	if rows, _ := ms.DHCPLeases(); len(rows) != 1 {
		t.Fatalf("stored leases = %+v, want the victim's row untouched", rows)
	}
	if n := len(s.opts.Alloc.quarantine); n != 0 {
		t.Fatalf("quarantine holds %d addresses, want none: no client declined an address it holds", n)
	}
}

// The quarantine map is fed by unauthenticated packets, so an address outside
// the pool must not put an entry in it even when the sender genuinely holds
// it. Declined from the holder, so the sender check passes and the range check
// is what has to stop it: Load restores out-of-range rows after an operator
// narrows the range, and a reservation commits in or out of it.
func TestDeclineOutsideTheRangeIsNotQuarantined(t *testing.T) {
	s, _ := newTestServer(t)
	const mac = "bb:bb:bb:bb:bb:bb"
	outside := netip.MustParseAddr("192.168.1.250")
	s.opts.Alloc.Load([]Lease{{MAC: mac, IP: outside, Hostname: "nas", Expires: epoch.Add(time.Hour)}})

	dec := discover(mac, "")
	dec.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeDecline))
	dec.UpdateOption(dhcpv4.OptRequestedIPAddress(net.IP(outside.AsSlice())))
	s.handle(&captureConn{}, &net.UDPAddr{IP: net.IPv4zero}, dec)

	if ls := s.opts.Alloc.Leases(); len(ls) != 0 {
		t.Fatalf("leases = %+v, want the holder's own decline to have dropped it", ls)
	}
	if n := len(s.opts.Alloc.quarantine); n != 0 {
		t.Fatalf("quarantine holds %d addresses, want none: %v is not ours to quarantine", n, outside)
	}
}

// A DECLINE with no chaddr names no client, and an empty MAC compares equal to
// the zero value byIP returns for a free address. One sweep would quarantine
// the whole pool from any host on the segment, and no new client could get an
// address for ten minutes.
func TestAnonymousDeclineQuarantinesNothing(t *testing.T) {
	s, ms := newTestServer(t)
	var rebuilds int
	s.opts.OnChange = func() { rebuilds++ }

	for _, ip := range []string{"192.168.1.10", "192.168.1.11", "192.168.1.12"} {
		s.handle(&captureConn{}, &net.UDPAddr{IP: net.IPv4zero},
			anonymous(t, dhcpv4.MessageTypeDecline, netip.MustParseAddr(ip)))
	}

	if n := len(s.opts.Alloc.quarantine); n != 0 {
		t.Fatalf("an anonymous DECLINE sweep quarantined %d addresses, want none", n)
	}
	if ms.dels != 0 || rebuilds != 0 {
		t.Fatalf("an anonymous DECLINE sweep drove %d store deletes and %d zone rebuilds, want none",
			ms.dels, rebuilds)
	}
	c := &captureConn{}
	s.handle(c, &net.UDPAddr{IP: net.IPv4zero}, discover("aa:aa:aa:aa:aa:aa", "laptop"))
	if n := len(c.replies(t)); n != 1 {
		t.Fatalf("a legitimate client got %d replies after the sweep, want an OFFER", n)
	}
}

// The same hole through a different door: RELEASE had no sender check at all,
// so every anonymous packet was a store delete plus a synchronous zone rebuild.
func TestAnonymousReleaseChangesNothing(t *testing.T) {
	s, ms := newTestServer(t)
	c := &captureConn{}
	s.handle(c, &net.UDPAddr{IP: net.IPv4zero}, request("aa:aa:aa:aa:aa:aa", "nas", netip.Addr{}))
	var rebuilds int
	s.opts.OnChange = func() { rebuilds++ }

	s.handle(&captureConn{}, &net.UDPAddr{IP: net.IPv4zero},
		anonymous(t, dhcpv4.MessageTypeRelease, netip.Addr{}))

	if ms.dels != 0 || rebuilds != 0 {
		t.Fatalf("an anonymous RELEASE drove %d store deletes and %d zone rebuilds, want none",
			ms.dels, rebuilds)
	}
	if rows, _ := ms.DHCPLeases(); len(rows) != 1 {
		t.Fatalf("stored leases = %+v, want the nas row untouched", rows)
	}
}

// The poller compares an order-sensitive digest of the lease set, and the
// allocator holds leases in a map. Unsorted, an unchanged set would look
// different on most polls and rebuild every zone snapshot.
func TestLeasesAreOrderedByAddress(t *testing.T) {
	s, _ := newTestServer(t)
	for _, mac := range []string{"cc:cc:cc:cc:cc:cc", "aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb"} {
		s.handle(&captureConn{}, &net.UDPAddr{IP: net.IPv4zero}, request(mac, "h"+mac[:2], netip.Addr{}))
	}
	want := []string{"192.168.1.10", "192.168.1.11", "192.168.1.12"}
	for i := 0; i < 20; i++ {
		ls, err := s.Leases(context.Background())
		if err != nil {
			t.Fatalf("Leases: %v", err)
		}
		got := make([]string, 0, len(ls))
		for _, l := range ls {
			got = append(got, l.IP)
		}
		if !slices.Equal(got, want) {
			t.Fatalf("Leases order = %v, want %v", got, want)
		}
	}
}

// server4.Serve runs one goroutine per packet, so the hostname arbitration
// has to be part of the commit: a check that released the lock first lets two
// clients hold one name and the published A record flaps between them.
func TestConcurrentRequestsCannotShareAHostname(t *testing.T) {
	macs := []string{"aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb", "cc:cc:cc:cc:cc:cc"}
	// Rounds, because one interleaving proves nothing: a check that released
	// the lock before committing loses this race only sometimes.
	for round := 0; round < 50; round++ {
		s, _ := newTestServer(t)
		var wg sync.WaitGroup
		for _, mac := range macs {
			wg.Add(1)
			go func() {
				defer wg.Done()
				s.handle(&captureConn{}, &net.UDPAddr{IP: net.IPv4zero}, request(mac, "laptop", netip.Addr{}))
			}()
		}
		wg.Wait()

		ls, err := s.Leases(context.Background())
		if err != nil {
			t.Fatalf("Leases: %v", err)
		}
		if len(ls) != 1 {
			t.Fatalf("round %d: %d leases hold the hostname \"laptop\" at once: %+v", round, len(ls), ls)
		}
	}
}

// A client that names an address it cannot have is NAKed rather than handed a
// different one: the spec's promoted replica NAKs the clients it does not
// know, and RFC 2131 4.3.2 says the same.
func TestRequestForAnInSubnetAddressOutsideThePoolIsNaked(t *testing.T) {
	s, _ := newTestServer(t)
	c := &captureConn{}
	s.handle(c, &net.UDPAddr{IP: net.IPv4zero},
		request("aa:aa:aa:aa:aa:aa", "laptop", netip.MustParseAddr("192.168.1.50")))

	replies := c.replies(t)
	if len(replies) != 1 || replies[0].MessageType() != dhcpv4.MessageTypeNak {
		t.Fatalf("replies = %+v, want one NAK, not an offer of some other address", replies)
	}
}

func TestRenewalOfALeaseWeDoNotKnowIsNaked(t *testing.T) {
	s, _ := newTestServer(t)
	// RENEWING: ciaddr carries the address, and there is no option 50.
	m := request("aa:aa:aa:aa:aa:aa", "laptop", netip.Addr{})
	m.ClientIPAddr = net.IP{192, 168, 1, 11}
	c := &captureConn{}
	s.handle(c, &net.UDPAddr{IP: net.IPv4zero}, m)

	replies := c.replies(t)
	if len(replies) != 1 || replies[0].MessageType() != dhcpv4.MessageTypeNak {
		t.Fatalf("replies = %+v, want one NAK", replies)
	}
}

func TestRenewalOfALeaseWeDoKnowIsAcked(t *testing.T) {
	s, _ := newTestServer(t)
	c := &captureConn{}
	s.handle(c, &net.UDPAddr{IP: net.IPv4zero}, request("aa:aa:aa:aa:aa:aa", "laptop", netip.Addr{}))
	held := c.replies(t)[0].YourIPAddr

	m := request("aa:aa:aa:aa:aa:aa", "laptop", netip.Addr{})
	m.ClientIPAddr = held
	c2 := &captureConn{}
	s.handle(c2, &net.UDPAddr{IP: net.IPv4zero}, m)

	replies := c2.replies(t)
	if len(replies) != 1 || replies[0].MessageType() != dhcpv4.MessageTypeAck {
		t.Fatalf("replies = %+v, want one ACK for the address the client already holds", replies)
	}
	if !replies[0].YourIPAddr.Equal(held) {
		t.Fatalf("renewal moved the client to %v, want %v", replies[0].YourIPAddr, held)
	}
}

// The seam the periodic probe needs: while our listener is bound it answers
// the probe like any other server, and nothing in the reply tells the two
// apart. Dropping the probe's own transaction is what separates them.
func TestIgnoreXIDDropsOnlyThatTransactionAndOnlyWhileHeld(t *testing.T) {
	s, _ := newTestServer(t)
	c := &captureConn{}
	peer := &net.UDPAddr{IP: net.IPv4zero}
	ours := discover("02:00:00:00:00:01", "")

	restore := s.ignoreXID(ours.TransactionID)
	s.handle(c, peer, ours)
	if got := c.replies(t); len(got) != 0 {
		t.Fatalf("our own listener answered its own probe with %+v", got)
	}
	s.handle(c, peer, discover("aa:aa:aa:aa:aa:aa", "laptop"))
	if got := c.replies(t); len(got) != 1 {
		t.Fatalf("replies = %+v, want a real client's DISCOVER answered while a probe is out", got)
	}

	restore()
	s.handle(c, peer, ours)
	if got := c.replies(t); len(got) != 2 {
		t.Fatalf("replies = %+v, want the drop to end with the probe: that MAC can never get an address otherwise", got)
	}
}

// A reservation is a promise about where a client ends up, not a licence for
// one broadcast packet to evict the client that is using the address now.
func TestDiscoverFromAReservedMACDoesNotEvictTheHolder(t *testing.T) {
	s, ms := newTestServer(t)
	const holder, reserved = "aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb"
	c := &captureConn{}
	s.handle(c, &net.UDPAddr{IP: net.IPv4zero}, request(holder, "nas", netip.Addr{}))
	held := c.replies(t)[0].YourIPAddr
	before, _ := ms.DHCPLeases()
	if len(before) != 1 {
		t.Fatalf("setup: persisted %+v, want one nas lease", before)
	}
	s.opts.Alloc.SetReservations(map[string]netip.Addr{reserved: netip.MustParseAddr(held.String())})

	c2 := &captureConn{}
	s.handle(c2, &net.UDPAddr{IP: net.IPv4zero}, discover(reserved, ""))

	replies := c2.replies(t)
	if len(replies) != 1 {
		t.Fatalf("got %d replies to a DISCOVER, want 1", len(replies))
	}
	if got := replies[0].YourIPAddr; got.Equal(held) {
		t.Fatalf("offered %v to the reserved client while another still holds it", got)
	}
	ls, _ := s.Leases(t.Context())
	if len(ls) != 1 || ls[0].MAC != holder || ls[0].IP != held.String() || ls[0].Hostname != "nas" {
		t.Fatalf("leases = %+v, want nas still at %v", ls, held)
	}
	if want := epoch.Add(24 * time.Hour); !ls[0].Expires.Equal(want) {
		t.Fatalf("expiry = %v, want the full term %v", ls[0].Expires, want)
	}
	if got, _ := ms.DHCPLeases(); len(got) != 1 || got[0] != before[0] {
		t.Fatalf("stored lease = %+v, want %+v untouched", got, before[0])
	}
}

// Moving a client to a newly reserved address is legitimate; doing it on a
// DISCOVER, while the client is still using the old one, is not.
func TestDiscoverDoesNotMoveAClientOntoANewReservation(t *testing.T) {
	s, ms := newTestServer(t)
	const mac = "aa:aa:aa:aa:aa:aa"
	c := &captureConn{}
	s.handle(c, &net.UDPAddr{IP: net.IPv4zero}, request(mac, "nas", netip.Addr{}))
	held := c.replies(t)[0].YourIPAddr
	before, _ := ms.DHCPLeases()
	res := netip.MustParseAddr("192.168.1.11")
	s.opts.Alloc.SetReservations(map[string]netip.Addr{mac: res})

	c2 := &captureConn{}
	s.handle(c2, &net.UDPAddr{IP: net.IPv4zero}, discover(mac, ""))

	replies := c2.replies(t)
	if len(replies) != 1 {
		t.Fatalf("got %d replies to a DISCOVER, want 1", len(replies))
	}
	if got := replies[0].YourIPAddr; got.String() != res.String() {
		t.Fatalf("offered %v, want the reserved %v", got, res)
	}
	ls, _ := s.Leases(t.Context())
	if len(ls) != 1 || ls[0].IP != held.String() || ls[0].Hostname != "nas" {
		t.Fatalf("leases = %+v, want nas still at %v until the client commits", ls, held)
	}
	if want := epoch.Add(24 * time.Hour); !ls[0].Expires.Equal(want) {
		t.Fatalf("expiry = %v, want the full term %v", ls[0].Expires, want)
	}
	if got, _ := ms.DHCPLeases(); len(got) != 1 || got[0] != before[0] {
		t.Fatalf("stored lease = %+v, want %+v untouched", got, before[0])
	}
}

// The committing path is unchanged: the REQUEST the offer promised does move
// the client onto its reservation, name and full term intact.
func TestRequestMovesAClientOntoItsReservation(t *testing.T) {
	s, ms := newTestServer(t)
	const mac = "aa:aa:aa:aa:aa:aa"
	s.handle(&captureConn{}, &net.UDPAddr{IP: net.IPv4zero}, request(mac, "nas", netip.Addr{}))
	res := netip.MustParseAddr("192.168.1.11")
	s.opts.Alloc.SetReservations(map[string]netip.Addr{mac: res})

	c := &captureConn{}
	s.handle(c, &net.UDPAddr{IP: net.IPv4zero}, discover(mac, ""))
	offered := c.replies(t)[0].YourIPAddr

	c2 := &captureConn{}
	s.handle(c2, &net.UDPAddr{IP: net.IPv4zero}, request(mac, "nas", netip.MustParseAddr(offered.String())))
	reply := c2.replies(t)[0]
	if reply.MessageType() != dhcpv4.MessageTypeAck {
		t.Fatalf("REQUEST for the offered %v got %v, want ACK", offered, reply.MessageType())
	}
	if reply.YourIPAddr.String() != res.String() {
		t.Fatalf("acked %v, want the reserved %v", reply.YourIPAddr, res)
	}
	ls, _ := s.Leases(t.Context())
	if len(ls) != 1 || ls[0].IP != res.String() || ls[0].Hostname != "nas" {
		t.Fatalf("leases = %+v, want nas at the reserved %v", ls, res)
	}
	got, _ := ms.DHCPLeases()
	if len(got) != 1 || got[0].IP != res.String() || got[0].ExpiresAt != epoch.Add(24*time.Hour).Unix() {
		t.Fatalf("persisted %+v, want one full-term lease at %v", got, res)
	}
}

// Refusing to evict on the DISCOVER does not strand the reservation: the
// REQUEST that follows takes it, displaces the incumbent, and the client
// converges on it one DORA round later.
func TestAReservedClientReachesAHeldAddressThroughRequest(t *testing.T) {
	s, ms := newTestServer(t)
	const holder, reserved = "aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb"
	c := &captureConn{}
	s.handle(c, &net.UDPAddr{IP: net.IPv4zero}, request(holder, "nas", netip.Addr{}))
	held := netip.MustParseAddr(c.replies(t)[0].YourIPAddr.String())
	s.opts.Alloc.SetReservations(map[string]netip.Addr{reserved: held})

	// Round one: offered a dynamic address, NAKed for it, and the incumbent
	// is displaced by that REQUEST.
	c2 := &captureConn{}
	s.handle(c2, &net.UDPAddr{IP: net.IPv4zero}, discover(reserved, ""))
	offered := c2.replies(t)[0].YourIPAddr
	c3 := &captureConn{}
	s.handle(c3, &net.UDPAddr{IP: net.IPv4zero}, request(reserved, "", netip.MustParseAddr(offered.String())))
	if got := c3.replies(t)[0].MessageType(); got != dhcpv4.MessageTypeNak {
		t.Fatalf("REQUEST for %v got %v, want NAK: the reservation is elsewhere", offered, got)
	}

	// Round two: the reservation is now the client's own, so it is offered
	// and acked.
	c4 := &captureConn{}
	s.handle(c4, &net.UDPAddr{IP: net.IPv4zero}, discover(reserved, ""))
	if got := c4.replies(t)[0].YourIPAddr; got.String() != held.String() {
		t.Fatalf("second offer = %v, want the reserved %v", got, held)
	}
	c5 := &captureConn{}
	s.handle(c5, &net.UDPAddr{IP: net.IPv4zero}, request(reserved, "backup", held))
	reply := c5.replies(t)[0]
	if reply.MessageType() != dhcpv4.MessageTypeAck || reply.YourIPAddr.String() != held.String() {
		t.Fatalf("second REQUEST got %v for %v, want an ACK for %v", reply.MessageType(), reply.YourIPAddr, held)
	}
	got, _ := ms.DHCPLeases()
	if len(got) != 1 || got[0].MAC != reserved || got[0].IP != held.String() {
		t.Fatalf("persisted %+v, want the reserved client alone at %v", got, held)
	}
}

// The same hole at the packet layer, from a reservation map alone: one bare
// DISCOVER from a client whose reservation is occupied and whose own address
// is reserved elsewhere used to drop its name out of DNS.
func TestDiscoverKeepsALiveLeaseWhenTheReservationRulesBothRefuse(t *testing.T) {
	s, ms := newTestServer(t)
	const macA, macB, macC = "aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb", "cc:cc:cc:cc:cc:cc"
	peer := &net.UDPAddr{IP: net.IPv4zero}
	c := &captureConn{}
	s.handle(c, peer, request(macA, "nas", netip.Addr{}))
	first := netip.MustParseAddr(c.replies(t)[0].YourIPAddr.String())
	c2 := &captureConn{}
	s.handle(c2, peer, request(macB, "backup", netip.Addr{}))
	second := netip.MustParseAddr(c2.replies(t)[0].YourIPAddr.String())
	before, _ := ms.DHCPLeases()
	s.opts.Alloc.SetReservations(map[string]netip.Addr{macB: first, macC: second})

	c3 := &captureConn{}
	s.handle(c3, peer, discover(macB, ""))

	replies := c3.replies(t)
	if len(replies) != 1 {
		t.Fatalf("got %d replies to a DISCOVER, want 1", len(replies))
	}
	if got := replies[0].YourIPAddr; got.String() != second.String() {
		t.Fatalf("offered %v, want the %v the client is still using", got, second)
	}
	ls, _ := s.Leases(t.Context())
	if len(ls) != 2 {
		t.Fatalf("leases = %+v, want both clients still named in DNS", ls)
	}
	for _, l := range ls {
		if l.MAC != macB {
			continue
		}
		if l.IP != second.String() || l.Hostname != "backup" || !l.Expires.Equal(epoch.Add(24*time.Hour)) {
			t.Fatalf("lease = %+v, want backup still at %v for the full term", l, second)
		}
	}
	if got, _ := ms.DHCPLeases(); len(got) != len(before) {
		t.Fatalf("stored leases = %+v, want %+v untouched", got, before)
	}
}

// An OFFER promises a reservation without leasing it, so Decline refuses a
// client that declines one. The operator still has to hear about it: a
// reserved address something else answers to is a configuration problem, not
// the forged packet the generic message describes.
func TestDeclineForAPromisedReservationTellsTheOperator(t *testing.T) {
	s, _ := newTestServer(t)
	var buf bytes.Buffer
	s.opts.Logger = slog.New(slog.NewTextHandler(&buf, nil))
	const mac = "aa:aa:aa:aa:aa:aa"
	res := netip.MustParseAddr("192.168.1.11")
	peer := &net.UDPAddr{IP: net.IPv4zero}
	s.handle(&captureConn{}, peer, request(mac, "nas", netip.Addr{})) // a live lease elsewhere
	s.opts.Alloc.SetReservations(map[string]netip.Addr{mac: res})
	s.handle(&captureConn{}, peer, discover(mac, "")) // promises res without leasing it

	dec := discover(mac, "")
	dec.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeDecline))
	dec.UpdateOption(dhcpv4.OptRequestedIPAddress(net.IP(res.AsSlice())))
	s.handle(&captureConn{}, peer, dec)
	got := buf.String()
	if strings.Contains(got, "does not hold") {
		t.Fatalf("logged a forged-packet message for a squatted reservation: %s", got)
	}
	if !strings.Contains(got, "reserved address is already in use") {
		t.Fatalf("log = %q, want the operator told the reservation is in use", got)
	}

	// The generic message still covers the case it was written for.
	buf.Reset()
	other := discover("bb:bb:bb:bb:bb:bb", "")
	other.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeDecline))
	other.UpdateOption(dhcpv4.OptRequestedIPAddress(net.IP(netip.MustParseAddr("192.168.1.10").AsSlice())))
	s.handle(&captureConn{}, peer, other)
	if got := buf.String(); !strings.Contains(got, "does not hold") {
		t.Fatalf("log = %q, want a decline from a client holding nothing still called out", got)
	}
}

// The same hole at the packet layer, and the harm it does: a client whose
// persisted address is now the server's own is offered it, REQUESTs it, and
// is NAKed — a DORA loop it can never leave.
func TestDiscoverForAClientOnAProtectedAddressConverges(t *testing.T) {
	s, _ := newTestServer(t)
	const mac = "aa:aa:aa:aa:aa:aa"
	peer := &net.UDPAddr{IP: net.IPv4zero}
	host := testConfig().Host
	s.opts.Alloc.Load([]Lease{{MAC: mac, IP: host, Hostname: "nas", Expires: epoch.Add(24 * time.Hour)}})

	c := &captureConn{}
	s.handle(c, peer, discover(mac, ""))
	offered := c.replies(t)[0].YourIPAddr
	if offered.String() == host.String() {
		t.Fatalf("offered %v, which is the server's own address", offered)
	}

	c2 := &captureConn{}
	s.handle(c2, peer, request(mac, "nas", netip.MustParseAddr(offered.String())))
	reply := c2.replies(t)[0]
	if reply.MessageType() != dhcpv4.MessageTypeAck {
		t.Fatalf("REQUEST for the offered %v got %v, want an ACK", offered, reply.MessageType())
	}
}
