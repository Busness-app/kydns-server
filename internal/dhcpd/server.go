package dhcpd

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/server4"
	idhcp "github.com/yoshiofthewire/kydns-server/internal/discovery/dhcp"
	"github.com/yoshiofthewire/kydns-server/internal/store"
)

// The whole point of this package's shape: leases reach DNS through the path
// lease-file discovery already uses.
var _ idhcp.Source = (*Server)(nil)

// offerHold is how long a DISCOVER's tentative address is held. Most
// DISCOVERs are never followed by a REQUEST, so an OFFER is a short
// reservation, not a lease: holding the full lease term for one would let a
// flood of forged DISCOVERs exhaust the pool with no ACK ever sent.
const offerHold = 60 * time.Second

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

	mu     sync.Mutex
	srv    *server4.Server
	cancel context.CancelFunc
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
	// Start owns its own cancellation, not just the caller's: Stop must be
	// able to end the watcher goroutine below on its own, whether or not the
	// caller ever cancels ctx (Task 10 calls Start(context.Background())).
	runCtx, cancel := context.WithCancel(ctx)
	s.mu.Lock()
	s.srv = srv
	s.cancel = cancel
	s.mu.Unlock()

	go func() {
		<-runCtx.Done()
		_ = s.Stop()
	}()
	go func() {
		if err := srv.Serve(); err != nil && runCtx.Err() == nil {
			s.opts.Logger.Error("dhcp server stopped", "error", err)
		}
	}()
	return nil
}

// Stop is idempotent: it is called both by an admin-initiated reconfigure and
// by the watcher goroutine started in Start. cancel runs before srv.Close so
// the watcher's context is already done, and Serve's resulting read error is
// recognized as an intentional stop rather than logged as a crash.
func (s *Server) Stop() error {
	s.mu.Lock()
	srv := s.srv
	cancel := s.cancel
	s.srv = nil
	s.cancel = nil
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
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
// for an OFFER, which takes a tentative hold through Alloc.Offer: it lasts
// offerHold only and never claims a name, because only a client that reaches
// REQUEST is trusted enough for either. Option 12 is client-chosen, so a bare
// DISCOVER must not be able to plant a name in Leases() by itself, nor to cut
// short a lease the same client already holds.
func (s *Server) allocate(mac string, m *dhcpv4.DHCPv4, commit bool) (Lease, bool) {
	var requested netip.Addr
	if ip, ok := netip.AddrFromSlice(m.RequestedIPAddress()); ok {
		requested = ip.Unmap()
	}
	if !commit {
		l, fresh, ok := s.opts.Alloc.Offer(mac, requested, offerHold)
		if !ok {
			return Lease{}, false
		}
		// Only an address new to this client is probed. A renewal or a
		// reservation is one it is already entitled to, and its own answer
		// would quarantine the address out from under it.
		if fresh && s.opts.Prober.InUse(l.IP) {
			s.opts.Logger.Warn("an address in the pool answered a probe; quarantining it", "ip", l.IP)
			s.opts.Alloc.Quarantine(l.IP)
			s.opts.Alloc.Release(mac)
			l, _, ok = s.opts.Alloc.Offer(mac, netip.Addr{}, offerHold)
			return l, ok
		}
		return l, true
	}
	hostname := sanitizeHostname(m.HostName())
	if hostname != "" && s.opts.Alloc.NameTaken(hostname, mac) {
		s.opts.Logger.Warn("two clients claim one hostname; the later one gets an address and no name",
			"hostname", hostname, "mac", mac)
		hostname = ""
	}
	return s.opts.Alloc.Allocate(mac, hostname, requested, s.opts.Cfg.LeaseTime)
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

// normalizeMAC is the one form a MAC is stored and compared in. It parses so
// that a reservation typed with dashes, without zero-padding, or with no
// separators at all still compares equal to what ClientHWAddr.String()
// produces; a MAC that does not parse falls back to a trimmed, lowercased
// copy rather than being dropped.
func normalizeMAC(s string) string {
	s = strings.TrimSpace(s)
	if hw, err := net.ParseMAC(s); err == nil {
		return hw.String()
	}
	return strings.ToLower(s)
}

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
