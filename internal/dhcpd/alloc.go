package dhcpd

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"time"
)

// quarantineFor is how long an address that answered a probe, or that a
// client declined, is kept out of the pool. It is in memory only: losing it
// on restart costs one probe.
const quarantineFor = 10 * time.Minute

// Lease is one address the server has committed to a client.
type Lease struct {
	MAC      string
	IP       netip.Addr
	Hostname string
	Expires  time.Time
}

// Config is the pool. Host is our own address and Gateway the router's;
// both are excluded from allocation even when the range covers them, because
// an operator who typed a wide range did not mean to give away either.
type Config struct {
	Subnet    netip.Prefix
	Start     netip.Addr
	End       netip.Addr
	Host      netip.Addr
	Gateway   netip.Addr
	LeaseTime time.Duration
}

// Allocator owns address assignment. It holds no sockets and does no I/O, so
// every rule in it is testable against a fake clock.
type Allocator struct {
	now func() time.Time

	mu         sync.Mutex
	cfg        Config
	byMAC      map[string]Lease
	byIP       map[netip.Addr]string
	reserved   map[string]netip.Addr
	reservedIP map[netip.Addr]string
	quarantine map[netip.Addr]time.Time
}

func NewAllocator(cfg Config, now func() time.Time) *Allocator {
	if now == nil {
		now = time.Now
	}
	return &Allocator{
		now:        now,
		cfg:        cfg,
		byMAC:      map[string]Lease{},
		byIP:       map[netip.Addr]string{},
		reserved:   map[string]netip.Addr{},
		reservedIP: map[netip.Addr]string{},
		quarantine: map[netip.Addr]time.Time{},
	}
}

// Load restores persisted leases at startup. It replaces whatever is held,
// so it is a boot-time call, not an incremental one.
func (a *Allocator) Load(ls []Lease) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.byMAC, a.byIP = map[string]Lease{}, map[netip.Addr]string{}
	for _, l := range ls {
		a.byMAC[l.MAC] = l
		a.byIP[l.IP] = l.MAC
	}
}

// SetReservations replaces the MAC-to-address reservations. Part 2 feeds this
// from services; until then it is only ever set to an empty map.
func (a *Allocator) SetReservations(r map[string]netip.Addr) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.reserved = map[string]netip.Addr{}
	a.reservedIP = map[netip.Addr]string{}
	for mac, ip := range r {
		a.reserved[mac] = ip
		a.reservedIP[ip] = mac
	}
}

// Allocate returns the address this client should get, committing it. The
// bool is false only when the pool is exhausted.
func (a *Allocator) Allocate(mac, hostname string, requested netip.Addr) (Lease, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()

	commit := func(ip netip.Addr) (Lease, bool) {
		if held, ok := a.byIP[ip]; ok && held != mac {
			delete(a.byMAC, held)
		}
		if prev, ok := a.byMAC[mac]; ok && prev.IP != ip {
			delete(a.byIP, prev.IP)
		}
		l := Lease{MAC: mac, IP: ip, Hostname: hostname, Expires: now.Add(a.cfg.LeaseTime)}
		a.byMAC[mac] = l
		a.byIP[ip] = mac
		return l, true
	}

	// 1. A reservation always wins, in or out of the dynamic range, but
	// never our own address or the gateway.
	if ip, ok := a.reserved[mac]; ok && !a.protected(ip) {
		return commit(ip)
	}
	// 2. Renew what this client already holds, if it is still ours to give.
	if l, ok := a.byMAC[mac]; ok && a.usable(l.IP) && a.reservedIP[l.IP] == "" {
		return commit(l.IP)
	}
	// 3. Honour a requested address that is free.
	if requested.IsValid() && a.free(requested, mac, now) {
		return commit(requested)
	}
	// 4. Lowest free address in the range.
	for ip := a.cfg.Start; a.inRange(ip); ip = ip.Next() {
		if a.free(ip, mac, now) {
			return commit(ip)
		}
	}
	return Lease{}, false
}

// Release drops a client's lease, as a DHCPRELEASE does.
func (a *Allocator) Release(mac string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if l, ok := a.byMAC[mac]; ok {
		delete(a.byIP, l.IP)
		delete(a.byMAC, mac)
	}
}

// Decline quarantines an address a client rejected as already in use.
func (a *Allocator) Decline(ip netip.Addr) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if mac, ok := a.byIP[ip]; ok {
		delete(a.byMAC, mac)
		delete(a.byIP, ip)
	}
	a.quarantine[ip] = a.now().Add(quarantineFor)
}

// Quarantine keeps an address out of the pool, for a probe that found it in
// use by something we did not hand it to.
func (a *Allocator) Quarantine(ip netip.Addr) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.quarantine[ip] = a.now().Add(quarantineFor)
}

// Leases returns the unexpired leases, for the DNS zone and the UI.
func (a *Allocator) Leases() []Lease {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	out := make([]Lease, 0, len(a.byMAC))
	for _, l := range a.byMAC {
		if l.Expires.After(now) {
			out = append(out, l)
		}
	}
	return out
}

// NameTaken reports whether an unexpired lease held by a different client
// already claims this hostname. Option 12 is chosen by the client, so first
// claim wins for the life of the lease and the loser gets no name.
func (a *Allocator) NameTaken(hostname, mac string) bool {
	if hostname == "" {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	for _, l := range a.byMAC {
		if l.MAC != mac && l.Hostname == hostname && l.Expires.After(now) {
			return true
		}
	}
	return false
}

// free reports whether ip can be given to mac right now. Callers hold a.mu.
func (a *Allocator) free(ip netip.Addr, mac string, now time.Time) bool {
	if !a.usable(ip) {
		return false
	}
	if until, ok := a.quarantine[ip]; ok && until.After(now) {
		return false
	}
	if holder, ok := a.reservedIP[ip]; ok && holder != mac {
		return false
	}
	if holder, ok := a.byIP[ip]; ok && holder != mac {
		if l, ok := a.byMAC[holder]; ok && l.Expires.After(now) {
			return false
		}
	}
	return true
}

// usable reports whether ip is one this server may hand out at all.
func (a *Allocator) usable(ip netip.Addr) bool {
	return a.inRange(ip) && !a.protected(ip)
}

// protected reports whether ip is one this server must never hand to a
// client whatever the configuration says: our own address, and the router's.
func (a *Allocator) protected(ip netip.Addr) bool {
	return ip == a.cfg.Host || ip == a.cfg.Gateway
}

func (a *Allocator) inRange(ip netip.Addr) bool {
	if !ip.Is4() || !a.cfg.Start.Is4() || !a.cfg.End.Is4() {
		return false
	}
	return u32(ip) >= u32(a.cfg.Start) && u32(ip) <= u32(a.cfg.End)
}

func u32(a netip.Addr) uint32 {
	b := a.As4()
	return binary.BigEndian.Uint32(b[:])
}
