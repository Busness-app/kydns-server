### Task 7: Packet handling

**Files:**
- Create: `internal/dhcpd/server.go`
- Test: `internal/dhcpd/server_test.go`
- Modify: `go.mod`, `go.sum`

**Interfaces:**
- Consumes: `Allocator`, `Prober`, `Config`, `IfaceInfo`.
- Produces:
  - `type Server struct { ... }` implementing `discovery/dhcp.Source`: `Leases(ctx) ([]dhcp.Lease, error)`, `Name() string`
  - `func New(opts Options) *Server`, `type Options struct { Iface IfaceInfo; Cfg Config; DNS []netip.Addr; Domain string; Alloc *Allocator; Prober Prober; Store LeaseStore; OnChange func(); Logger *slog.Logger }`
  - `type LeaseStore interface { DHCPLeases() ([]store.DHCPLease, error); PutDHCPLease(store.DHCPLease) error; DeleteDHCPLease(string) error; DeleteExpiredDHCPLeases(int64) (int, error) }`
  - `func (s *Server) handle(conn net.PacketConn, peer net.Addr, m *dhcpv4.DHCPv4)` — the unit every packet test drives.
  - `func (s *Server) Start(ctx context.Context) error`, `func (s *Server) Stop() error`

- [ ] **Step 1: Add the dependency and confirm the API surface**

The exact names of the reply modifiers matter and must not be guessed.

```bash
go get github.com/insomniacslk/dhcp@latest
go doc github.com/insomniacslk/dhcp/dhcpv4 NewReplyFromRequest
go doc github.com/insomniacslk/dhcp/dhcpv4 | grep -E '^func (With|Opt)'
go doc github.com/insomniacslk/dhcp/dhcpv4/server4 NewServer
go doc github.com/insomniacslk/dhcp/dhcpv4/server4 Handler
```

Expected: `NewReplyFromRequest(request *DHCPv4, modifiers ...Modifier) (*DHCPv4, error)`; modifiers including `WithMessageType`, `WithYourIP`, `WithServerIP`, `WithOption`; option constructors including `OptSubnetMask`, `OptRouter`, `OptDNS`, `OptIPAddressLeaseTime`, `OptServerIdentifier`, `OptDomainName`; `server4.NewServer(ifname string, addr *net.UDPAddr, handler Handler, opt ...ServerOpt)`; `type Handler func(conn net.PacketConn, peer net.Addr, m *dhcpv4.DHCPv4)`.

**If any name differs from the above, use what `go doc` reports and adjust the code in Step 3 to match.** Record the version you pinned in the commit message. Do not proceed on the assumption that this document is right and the module is wrong.

- [ ] **Step 2: Write the failing tests**

Create `internal/dhcpd/server_test.go`:

```go
package dhcpd

import (
	"log/slog"
	"net"
	"net/netip"
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
```

- [ ] **Step 3: Write the implementation**

Create `internal/dhcpd/server.go`. Adjust modifier and accessor names to whatever Step 1 reported.

```go
package dhcpd

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/server4"
	idhcp "github.com/yoshiofthewire/kydns-server/internal/discovery/dhcp"
	"github.com/yoshiofthewire/kydns-server/internal/store"
)

// LeaseStore is the store slice this package needs, named here so the
// package does not depend on the whole store.
type LeaseStore interface {
	DHCPLeases() ([]store.DHCPLease, error)
	PutDHCPLease(store.DHCPLease) error
	DeleteDHCPLease(string) error
	DeleteExpiredDHCPLeases(int64) (int, error)
}

type Options struct {
	Iface  IfaceInfo
	Cfg    Config
	DNS    []netip.Addr // option 6, ourselves first
	Domain string       // option 15
	Alloc  *Allocator
	Prober Prober
	Store  LeaseStore
	// OnChange is called when the lease set changes, so the zone snapshot
	// rebuilds immediately rather than at the next poll.
	OnChange func()
	Logger   *slog.Logger
	// Now is injected for tests. Nil means time.Now.
	Now func() time.Time
}

// Server is the built-in DHCPv4 server. It implements discovery/dhcp.Source.
type Server struct {
	opts Options
	now  func() time.Time

	mu  sync.Mutex
	srv *server4.Server
}

func New(o Options) *Server {
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Prober == nil {
		o.Prober = nopProber{}
	}
	if o.OnChange == nil {
		o.OnChange = func() {}
	}
	now := o.Now
	if now == nil {
		now = time.Now
	}
	return &Server{opts: o, now: now}
}

func (s *Server) Name() string { return "built-in" }

// Leases satisfies discovery/dhcp.Source. Only named, unexpired leases reach
// DNS: a client that sent no hostname gets an address and nothing else.
func (s *Server) Leases(context.Context) ([]idhcp.Lease, error) {
	var out []idhcp.Lease
	for _, l := range s.opts.Alloc.Leases() {
		if l.Hostname == "" {
			continue
		}
		out = append(out, idhcp.Lease{
			MAC: l.MAC, IP: l.IP.String(), Hostname: l.Hostname, Expires: l.Expires,
		})
	}
	return out, nil
}

// Start binds the listener. It does not check whether the interface
// qualifies: the caller does that, because the caller is the one that reports
// the reason to the operator.
func (s *Server) Start(ctx context.Context) error {
	if err := s.restore(); err != nil {
		return err
	}
	srv, err := server4.NewServer(
		s.opts.Iface.Name,
		&net.UDPAddr{IP: net.IPv4zero, Port: 67},
		s.handle)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.srv = srv
	s.mu.Unlock()

	go func() {
		<-ctx.Done()
		_ = s.Stop()
	}()
	go func() {
		if err := srv.Serve(); err != nil && ctx.Err() == nil {
			s.opts.Logger.Error("dhcp server stopped", "error", err)
		}
	}()
	return nil
}

func (s *Server) Stop() error {
	s.mu.Lock()
	srv := s.srv
	s.srv = nil
	s.mu.Unlock()
	if srv == nil {
		return nil
	}
	return srv.Close()
}

// restore loads persisted leases into the allocator, so a restart cannot
// re-issue an address that is still in use. Expired rows are pruned here
// rather than on a timer.
func (s *Server) restore() error {
	if _, err := s.opts.Store.DeleteExpiredDHCPLeases(s.now().Unix()); err != nil {
		return err
	}
	rows, err := s.opts.Store.DHCPLeases()
	if err != nil {
		return err
	}
	var ls []Lease
	for _, r := range rows {
		ip, err := netip.ParseAddr(r.IP)
		if err != nil {
			s.opts.Logger.Warn("dropping an unparseable stored lease", "mac", r.MAC, "ip", r.IP)
			continue
		}
		ls = append(ls, Lease{MAC: r.MAC, IP: ip, Hostname: r.Hostname, Expires: time.Unix(r.ExpiresAt, 0)})
	}
	s.opts.Alloc.Load(ls)
	return nil
}

// handle is the whole packet path. Every test drives this directly, so it
// takes the conn rather than reaching for one.
func (s *Server) handle(conn net.PacketConn, peer net.Addr, m *dhcpv4.DHCPv4) {
	if m == nil {
		return
	}
	mac := normalizeMAC(m.ClientHWAddr.String())
	switch m.MessageType() {
	case dhcpv4.MessageTypeDiscover:
		s.offer(conn, peer, m, mac)
	case dhcpv4.MessageTypeRequest:
		s.ack(conn, peer, m, mac)
	case dhcpv4.MessageTypeRelease:
		s.opts.Alloc.Release(mac)
		if err := s.opts.Store.DeleteDHCPLease(mac); err != nil {
			s.opts.Logger.Warn("could not delete a released lease", "mac", mac, "error", err)
		}
		s.opts.OnChange()
	case dhcpv4.MessageTypeDecline:
		if ip, ok := netip.AddrFromSlice(m.RequestedIPAddress()); ok {
			s.opts.Alloc.Decline(ip.Unmap())
			s.opts.Logger.Warn("client declined an address as already in use",
				"mac", mac, "ip", ip.Unmap())
		}
		if err := s.opts.Store.DeleteDHCPLease(mac); err != nil {
			s.opts.Logger.Warn("could not delete a declined lease", "mac", mac, "error", err)
		}
		s.opts.OnChange()
	case dhcpv4.MessageTypeInform:
		s.inform(conn, peer, m)
	default:
		// Anything else, including a message with no type at all, is dropped.
	}
}

func (s *Server) offer(conn net.PacketConn, peer net.Addr, m *dhcpv4.DHCPv4, mac string) {
	l, ok := s.allocate(mac, m, false)
	if !ok {
		s.opts.Logger.Warn("no free address to offer",
			"mac", mac, "range", s.opts.Cfg.Start.String()+"-"+s.opts.Cfg.End.String())
		return
	}
	s.reply(conn, peer, m, dhcpv4.MessageTypeOffer, l.IP)
}

func (s *Server) ack(conn net.PacketConn, peer net.Addr, m *dhcpv4.DHCPv4, mac string) {
	// A client asking to keep an address we do not control must be told so,
	// or it will sit on it until the lease it thinks it has runs out.
	if req, ok := netip.AddrFromSlice(m.RequestedIPAddress()); ok {
		r := req.Unmap()
		if r.IsValid() && !r.IsUnspecified() && !s.opts.Cfg.Subnet.Contains(r) {
			s.nak(conn, peer, m)
			return
		}
	}
	l, ok := s.allocate(mac, m, true)
	if !ok {
		s.nak(conn, peer, m)
		return
	}
	row := store.DHCPLease{
		MAC:       l.MAC,
		IP:        l.IP.String(),
		Hostname:  l.Hostname,
		ExpiresAt: l.Expires.Unix(),
		LastSeen:  s.now().Unix(),
	}
	if err := s.opts.Store.PutDHCPLease(row); err != nil {
		// The allocator has already committed; refusing now would leave the
		// two out of step. Serve the client and say the persistence failed.
		s.opts.Logger.Error("could not persist a lease", "mac", mac, "ip", row.IP, "error", err)
	}
	s.reply(conn, peer, m, dhcpv4.MessageTypeAck, l.IP)
	s.opts.OnChange()
}

// allocate runs the pool rules and the hostname arbitration. commit is false
// for an OFFER, which does not persist and does not claim a name.
func (s *Server) allocate(mac string, m *dhcpv4.DHCPv4, commit bool) (Lease, bool) {
	hostname := sanitizeHostname(m.HostName())
	if hostname != "" && s.opts.Alloc.NameTaken(hostname, mac) {
		s.opts.Logger.Warn("two clients claim one hostname; the later one gets an address and no name",
			"hostname", hostname, "mac", mac)
		hostname = ""
	}
	var requested netip.Addr
	if ip, ok := netip.AddrFromSlice(m.RequestedIPAddress()); ok {
		requested = ip.Unmap()
	}
	l, ok := s.opts.Alloc.Allocate(mac, hostname, requested)
	if !ok {
		return Lease{}, false
	}
	// Probe only an address that is new to us. A renewal or a reservation is
	// not probed: the client already has it, or it is spoken for.
	if !commit && s.opts.Prober.InUse(l.IP) {
		s.opts.Logger.Warn("an address in the pool answered a probe; quarantining it", "ip", l.IP)
		s.opts.Alloc.Quarantine(l.IP)
		s.opts.Alloc.Release(mac)
		return s.opts.Alloc.Allocate(mac, hostname, netip.Addr{})
	}
	return l, true
}

func (s *Server) reply(conn net.PacketConn, peer net.Addr, m *dhcpv4.DHCPv4, t dhcpv4.MessageType, yours netip.Addr) {
	self := net.IP(s.opts.Iface.Addr.AsSlice())
	mods := []dhcpv4.Modifier{
		dhcpv4.WithMessageType(t),
		dhcpv4.WithServerIP(self),
		dhcpv4.WithOption(dhcpv4.OptServerIdentifier(self)),
		dhcpv4.WithOption(dhcpv4.OptSubnetMask(net.CIDRMask(s.opts.Cfg.Subnet.Bits(), 32))),
		dhcpv4.WithOption(dhcpv4.OptIPAddressLeaseTime(s.opts.Cfg.LeaseTime)),
	}
	if yours.IsValid() {
		mods = append(mods, dhcpv4.WithYourIP(net.IP(yours.AsSlice())))
	}
	if s.opts.Cfg.Gateway.IsValid() {
		mods = append(mods, dhcpv4.WithOption(dhcpv4.OptRouter(net.IP(s.opts.Cfg.Gateway.AsSlice()))))
	}
	if dns := toIPs(s.opts.DNS); len(dns) > 0 {
		mods = append(mods, dhcpv4.WithOption(dhcpv4.OptDNS(dns...)))
	}
	if s.opts.Domain != "" {
		mods = append(mods, dhcpv4.WithOption(dhcpv4.OptDomainName(s.opts.Domain)))
	}
	s.send(conn, peer, m, mods...)
}

func (s *Server) nak(conn net.PacketConn, peer net.Addr, m *dhcpv4.DHCPv4) {
	self := net.IP(s.opts.Iface.Addr.AsSlice())
	s.send(conn, peer, m,
		dhcpv4.WithMessageType(dhcpv4.MessageTypeNak),
		dhcpv4.WithOption(dhcpv4.OptServerIdentifier(self)))
}

// inform answers a client that has an address already and wants only options.
// No lease is allocated and nothing is persisted.
func (s *Server) inform(conn net.PacketConn, peer net.Addr, m *dhcpv4.DHCPv4) {
	s.reply(conn, peer, m, dhcpv4.MessageTypeAck, netip.Addr{})
}

// send broadcasts the reply. Every reply is broadcast: a client that has no
// address yet cannot be reached by unicast without a raw socket, and one that
// does is still listening on 0.0.0.0:68.
func (s *Server) send(conn net.PacketConn, _ net.Addr, m *dhcpv4.DHCPv4, mods ...dhcpv4.Modifier) {
	reply, err := dhcpv4.NewReplyFromRequest(m, mods...)
	if err != nil {
		s.opts.Logger.Warn("could not build a dhcp reply", "error", err)
		return
	}
	dst := &net.UDPAddr{IP: net.IPv4bcast, Port: 68}
	if _, err := conn.WriteTo(reply.ToBytes(), dst); err != nil {
		s.opts.Logger.Warn("could not send a dhcp reply", "error", err)
	}
}

func toIPs(as []netip.Addr) []net.IP {
	out := make([]net.IP, 0, len(as))
	for _, a := range as {
		if a.IsValid() {
			out = append(out, net.IP(a.AsSlice()))
		}
	}
	return out
}
```

- [ ] **Step 4: Add the hostname and MAC helpers**

Still in `internal/dhcpd/server.go`:

```go
// normalizeMAC is the one form a MAC is stored and compared in: lowercase,
// colon-separated. Reservations in Part 2 normalize the same way, so the two
// always compare directly.
func normalizeMAC(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// sanitizeHostname reduces option 12 to something safe to publish as a DNS
// label, or to "" if it cannot be. Option 12 is chosen by any device on the
// segment, so this is untrusted input.
func sanitizeHostname(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if i := strings.IndexByte(h, '.'); i >= 0 {
		h = h[:i] // a client may send an FQDN; we own the domain
	}
	if h == "" || len(h) > 63 {
		return ""
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'
		if !ok {
			return ""
		}
	}
	if h[0] == '-' || h[len(h)-1] == '-' {
		return ""
	}
	return h
}
```

Add `"strings"` to the import block.

- [ ] **Step 5: Write the hostname tests**

Append to `internal/dhcpd/server_test.go`:

```go
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
```

Add `"strings"` to the test file's imports.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `go test ./internal/dhcpd/ -v`
Expected: PASS, every test in the package.

- [ ] **Step 7: Prove the source contract holds**

Run: `go build ./... && go vet ./internal/dhcpd/`
Expected: no output. Then add this compile-time assertion at the top of `internal/dhcpd/server.go`, below the imports, and rebuild:

```go
// The whole point of this package's shape: leases reach DNS through the path
// lease-file discovery already uses.
var _ idhcp.Source = (*Server)(nil)
```

Run: `go build ./internal/dhcpd/`
Expected: no output. A failure here means the interface drifted and the wiring in Task 8 will not compile.

- [ ] **Step 8: Commit**

```bash
git add go.mod go.sum internal/dhcpd/server.go internal/dhcpd/server_test.go
git commit -m "feat(dhcpd): DHCPv4 packet handling

DISCOVER/OFFER, REQUEST/ACK/NAK, DECLINE, RELEASE, INFORM. Implements
discovery/dhcp.Source, so leases reach DNS through the path lease-file
discovery already uses. Every packet test drives handle() against a fake
PacketConn; no test opens a socket.

Option 12 is client-chosen, so hostnames are sanitized to a single DNS
label and the second claim on a name gets an address and no name."
```

---

