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

// Allocate returns the address this client should get, committing it as a
// lease for ttl. The bool is false only when the pool is exhausted.
func (a *Allocator) Allocate(mac, hostname string, requested netip.Addr, ttl time.Duration) (Lease, bool) {
	l, _, ok := a.allocate(mac, hostname, requested, ttl, false)
	return l, ok
}

// Offer holds an address for a client that has only DISCOVERed. An OFFER is
// a tentative hold, not a lease, so it never weakens a lease the client
// already holds: neither the name nor the expiry of one moves. fresh is true
// only when the address is new to this client — rules 3 and 4 — which is the
// only case worth a conflict probe.
func (a *Allocator) Offer(mac string, requested netip.Addr, hold time.Duration) (l Lease, fresh, ok bool) {
	return a.allocate(mac, "", requested, hold, true)
}

func (a *Allocator) allocate(mac, hostname string, requested netip.Addr, ttl time.Duration, tentative bool) (Lease, bool, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()

	// First claim wins, decided here rather than by the caller: two REQUESTs
	// carrying one option 12 are handled on two goroutines, and a check that
	// released the lock before committing would let both through.
	if a.nameTakenLocked(hostname, mac, now) {
		hostname = ""
	}

	prev, hasPrev := a.byMAC[mac]
	held := hasPrev && prev.Expires.After(now) // a lease this client is still using

	commit := func(ip netip.Addr, fresh bool) (Lease, bool, bool) {
		if holder, ok := a.byIP[ip]; ok && holder != mac {
			delete(a.byMAC, holder)
		}
		if hasPrev && prev.IP != ip {
			delete(a.byIP, prev.IP)
		}
		l := Lease{MAC: mac, IP: ip, Hostname: hostname, Expires: now.Add(ttl)}
		// A tentative hold never weakens a live lease on the same address:
		// its name stays and its expiry only ever moves later.
		if tentative && held && prev.IP == ip {
			l.Hostname = prev.Hostname
			if prev.Expires.After(l.Expires) {
				l.Expires = prev.Expires
			}
		}
		a.byMAC[mac] = l
		a.byIP[ip] = mac
		return l, fresh, true
	}

	// 1. A reservation always wins, in or out of the dynamic range, but
	// never our own address or the gateway. A REQUEST takes it whatever is in
	// the way; a DISCOVER is not a lease operation, so it may promise the
	// reservation but never destroy a live lease to keep the promise.
	if ip, ok := a.reserved[mac]; ok && !a.protected(ip) {
		switch {
		case !tentative:
			return commit(ip, false)
		case a.heldByAnotherLocked(ip, mac, now):
			// Another client is still using it. Offering it would point two
			// clients at one address, so fall through to a dynamic one; the
			// REQUEST for that address still takes the reservation.
		case held && prev.IP != ip:
			// Promise the reservation without taking it. Nothing else can be
			// given the address anyway — free() bars a reserved address from
			// every other client — so only the REQUEST that commits the move
			// need drop the lease this client is still using.
			return Lease{MAC: mac, IP: ip, Expires: now.Add(ttl)}, false, true
		default:
			return commit(ip, false)
		}
	}
	// 2. Renew what this client already holds, if it is still ours to give.
	if l, ok := a.byMAC[mac]; ok && a.usable(l.IP) && a.reservedIP[l.IP] == "" {
		return commit(l.IP, !l.Expires.After(now)) // an expired holding is new to us again
	}
	// A tentative hold never moves a client off a lease it is still using:
	// rules 3 and 4 commit, and commit deletes the old entry. Reached only
	// when rules 1 and 2 have both refused, so the address may no longer be
	// ours to give — but the client is on it either way, and a DISCOVER is
	// not the moment to take it away. The REQUEST still decides. Our own
	// address and the gateway are the exception: they were never ours to
	// give, so returning one only loops the client through DISCOVER and NAK.
	if tentative && held && !a.protected(prev.IP) {
		return prev, false, true
	}
	// 3. Honour a requested address that is free.
	if requested.IsValid() && a.free(requested, mac, now) {
		return commit(requested, true)
	}
	// 4. Lowest free address in the range.
	for ip := a.cfg.Start; a.inRange(ip); ip = ip.Next() {
		if a.free(ip, mac, now) {
			return commit(ip, true)
		}
	}
	return Lease{}, false, false
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

// Decline quarantines an address a client rejected as already in use, and
// reports whether it dropped that client's lease. A DECLINE is an
// unauthenticated broadcast, so it is honoured only from the client that holds
// the address, and only for an address that is ours to hold back: otherwise one
// forged packet deletes any lease on the segment, and the quarantine map takes
// entries from anyone who can send UDP. An empty MAC is rejected outright,
// because byIP yields "" for every free address and would match it.
func (a *Allocator) Decline(mac string, ip netip.Addr) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if mac == "" || a.byIP[ip] != mac {
		return false
	}
	delete(a.byMAC, mac)
	delete(a.byIP, ip)
	if a.inRange(ip) {
		a.quarantine[ip] = a.now().Add(quarantineFor)
	}
	return true
}

// reservationFor is the address reserved to mac, if any. Package-internal:
// only the packet path uses it, to tell a squatted reservation apart from a
// forged decline.
func (a *Allocator) reservationFor(mac string) (netip.Addr, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	ip, ok := a.reserved[mac]
	return ip, ok
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

// nameTakenLocked reports whether an unexpired lease held by a different
// client already claims this hostname. Option 12 is chosen by the client, so
// first claim wins for the life of the lease and the loser gets no name.
// Callers hold a.mu.
func (a *Allocator) nameTakenLocked(hostname, mac string, now time.Time) bool {
	if hostname == "" {
		return false
	}
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
	return !a.heldByAnotherLocked(ip, mac, now)
}

// heldByAnotherLocked reports whether ip is under an unexpired lease belonging
// to some other client. Callers hold a.mu.
func (a *Allocator) heldByAnotherLocked(ip netip.Addr, mac string, now time.Time) bool {
	holder, ok := a.byIP[ip]
	if !ok || holder == mac {
		return false
	}
	l, ok := a.byMAC[holder]
	return ok && l.Expires.After(now)
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
