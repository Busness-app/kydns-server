### Task 5: The allocator

Pure logic, injected clock, no I/O and no sockets. This is where every allocation rule in the spec lives, so it gets the densest tests.

**Files:**
- Create: `internal/dhcpd/alloc.go`
- Test: `internal/dhcpd/alloc_test.go`

**Interfaces:**
- Consumes: `IfaceInfo` (Task 4) for the subnet and the host's own address.
- Produces:
  - `type Lease struct { MAC string; IP netip.Addr; Hostname string; Expires time.Time }`
  - `type Config struct { Subnet netip.Prefix; Start, End, Host, Gateway netip.Addr; LeaseTime time.Duration }`
  - `func NewAllocator(cfg Config, now func() time.Time) *Allocator`
  - `func (a *Allocator) Load(ls []Lease)`
  - `func (a *Allocator) SetReservations(r map[string]netip.Addr)`
  - `func (a *Allocator) Allocate(mac, hostname string, requested netip.Addr) (Lease, bool)`
  - `func (a *Allocator) Release(mac string)`
  - `func (a *Allocator) Decline(ip netip.Addr)`
  - `func (a *Allocator) Leases() []Lease`
  - `func (a *Allocator) Quarantine(ip netip.Addr)`
  - `func (a *Allocator) NameTaken(hostname, mac string) bool`

- [ ] **Step 1: Write the failing tests**

Create `internal/dhcpd/alloc_test.go`:

```go
package dhcpd

import (
	"net/netip"
	"testing"
	"time"
)

var epoch = time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)

func testConfig() Config {
	return Config{
		Subnet:    netip.MustParsePrefix("192.168.1.0/24"),
		Start:     netip.MustParseAddr("192.168.1.10"),
		End:       netip.MustParseAddr("192.168.1.12"),
		Host:      netip.MustParseAddr("192.168.1.5"),
		Gateway:   netip.MustParseAddr("192.168.1.1"),
		LeaseTime: 24 * time.Hour,
	}
}

func newTestAllocator(t *testing.T) (*Allocator, *time.Time) {
	t.Helper()
	now := epoch
	return NewAllocator(testConfig(), func() time.Time { return now }), &now
}

func TestAllocateTakesTheLowestFreeAddress(t *testing.T) {
	a, _ := newTestAllocator(t)
	l, ok := a.Allocate("aa:aa:aa:aa:aa:aa", "one", netip.Addr{})
	if !ok {
		t.Fatal("Allocate refused the first client on an empty pool")
	}
	if want := netip.MustParseAddr("192.168.1.10"); l.IP != want {
		t.Fatalf("first address = %v, want %v", l.IP, want)
	}
	l2, ok := a.Allocate("bb:bb:bb:bb:bb:bb", "two", netip.Addr{})
	if !ok {
		t.Fatal("Allocate refused the second client")
	}
	if want := netip.MustParseAddr("192.168.1.11"); l2.IP != want {
		t.Fatalf("second address = %v, want %v", l2.IP, want)
	}
}

func TestAllocateRenewsTheSameClient(t *testing.T) {
	a, now := newTestAllocator(t)
	first, _ := a.Allocate("aa:aa:aa:aa:aa:aa", "one", netip.Addr{})
	*now = now.Add(time.Hour)
	second, ok := a.Allocate("aa:aa:aa:aa:aa:aa", "one", netip.Addr{})
	if !ok {
		t.Fatal("Allocate refused a renewal")
	}
	if second.IP != first.IP {
		t.Fatalf("renewal moved the client from %v to %v", first.IP, second.IP)
	}
	if !second.Expires.After(first.Expires) {
		t.Fatalf("renewal did not extend the lease: %v then %v", first.Expires, second.Expires)
	}
}

func TestAllocateHonoursARequestedAddress(t *testing.T) {
	a, _ := newTestAllocator(t)
	want := netip.MustParseAddr("192.168.1.12")
	l, ok := a.Allocate("aa:aa:aa:aa:aa:aa", "one", want)
	if !ok {
		t.Fatal("Allocate refused a free requested address")
	}
	if l.IP != want {
		t.Fatalf("address = %v, want the requested %v", l.IP, want)
	}
}

func TestAllocateIgnoresARequestedAddressThatIsTaken(t *testing.T) {
	a, _ := newTestAllocator(t)
	taken, _ := a.Allocate("aa:aa:aa:aa:aa:aa", "one", netip.Addr{})
	l, ok := a.Allocate("bb:bb:bb:bb:bb:bb", "two", taken.IP)
	if !ok {
		t.Fatal("Allocate refused the second client entirely")
	}
	if l.IP == taken.IP {
		t.Fatalf("Allocate handed %v to a second client", l.IP)
	}
}

func TestAllocateIgnoresARequestedAddressOutsideTheRange(t *testing.T) {
	a, _ := newTestAllocator(t)
	l, ok := a.Allocate("aa:aa:aa:aa:aa:aa", "one", netip.MustParseAddr("192.168.1.200"))
	if !ok {
		t.Fatal("Allocate refused the client")
	}
	if want := netip.MustParseAddr("192.168.1.10"); l.IP != want {
		t.Fatalf("address = %v, want %v from inside the range", l.IP, want)
	}
}

func TestReservationWinsOverEverything(t *testing.T) {
	a, _ := newTestAllocator(t)
	reserved := netip.MustParseAddr("192.168.1.50") // deliberately outside the range
	a.SetReservations(map[string]netip.Addr{"aa:aa:aa:aa:aa:aa": reserved})
	l, ok := a.Allocate("aa:aa:aa:aa:aa:aa", "one", netip.MustParseAddr("192.168.1.11"))
	if !ok {
		t.Fatal("Allocate refused a reserved client")
	}
	if l.IP != reserved {
		t.Fatalf("address = %v, want the reserved %v", l.IP, reserved)
	}
}

func TestAReservedAddressIsNotHandedOutDynamically(t *testing.T) {
	a, _ := newTestAllocator(t)
	// Reserve an address that sits inside the dynamic range.
	a.SetReservations(map[string]netip.Addr{"cc:cc:cc:cc:cc:cc": netip.MustParseAddr("192.168.1.10")})
	l, ok := a.Allocate("aa:aa:aa:aa:aa:aa", "one", netip.Addr{})
	if !ok {
		t.Fatal("Allocate refused the client")
	}
	if want := netip.MustParseAddr("192.168.1.11"); l.IP != want {
		t.Fatalf("address = %v, want %v: .10 is reserved for another MAC", l.IP, want)
	}
}

func TestAllocateSkipsTheHostAndGateway(t *testing.T) {
	cfg := testConfig()
	cfg.Start = netip.MustParseAddr("192.168.1.1") // range now covers gateway and host
	cfg.End = netip.MustParseAddr("192.168.1.6")
	a := NewAllocator(cfg, func() time.Time { return epoch })
	l, ok := a.Allocate("aa:aa:aa:aa:aa:aa", "one", netip.Addr{})
	if !ok {
		t.Fatal("Allocate refused the client")
	}
	if l.IP == cfg.Gateway || l.IP == cfg.Host {
		t.Fatalf("Allocate handed out %v, which is the gateway or our own address", l.IP)
	}
	if want := netip.MustParseAddr("192.168.1.2"); l.IP != want {
		t.Fatalf("address = %v, want %v", l.IP, want)
	}
}

func TestQuarantinedAddressIsSkippedThenReleased(t *testing.T) {
	a, now := newTestAllocator(t)
	a.Quarantine(netip.MustParseAddr("192.168.1.10"))
	l, _ := a.Allocate("aa:aa:aa:aa:aa:aa", "one", netip.Addr{})
	if want := netip.MustParseAddr("192.168.1.11"); l.IP != want {
		t.Fatalf("address = %v, want %v while .10 is quarantined", l.IP, want)
	}

	*now = now.Add(quarantineFor + time.Second)
	a.Release("aa:aa:aa:aa:aa:aa")
	l2, _ := a.Allocate("bb:bb:bb:bb:bb:bb", "two", netip.Addr{})
	if want := netip.MustParseAddr("192.168.1.10"); l2.IP != want {
		t.Fatalf("address = %v, want %v once the quarantine has expired", l2.IP, want)
	}
}

func TestDeclineQuarantines(t *testing.T) {
	a, _ := newTestAllocator(t)
	l, _ := a.Allocate("aa:aa:aa:aa:aa:aa", "one", netip.Addr{})
	a.Decline(l.IP)
	l2, _ := a.Allocate("bb:bb:bb:bb:bb:bb", "two", netip.Addr{})
	if l2.IP == l.IP {
		t.Fatalf("Allocate re-offered %v after it was declined", l.IP)
	}
}

func TestExpiredLeasesAreReusable(t *testing.T) {
	a, now := newTestAllocator(t)
	first, _ := a.Allocate("aa:aa:aa:aa:aa:aa", "one", netip.Addr{})
	*now = now.Add(25 * time.Hour)
	l, ok := a.Allocate("bb:bb:bb:bb:bb:bb", "two", netip.Addr{})
	if !ok {
		t.Fatal("Allocate refused a client after every lease had expired")
	}
	if l.IP != first.IP {
		t.Fatalf("address = %v, want the expired %v to be reused", l.IP, first.IP)
	}
}

func TestExhaustionRefuses(t *testing.T) {
	a, _ := newTestAllocator(t)
	for _, mac := range []string{"aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb", "cc:cc:cc:cc:cc:cc"} {
		if _, ok := a.Allocate(mac, "x", netip.Addr{}); !ok {
			t.Fatalf("Allocate refused %s while the pool still had room", mac)
		}
	}
	if _, ok := a.Allocate("dd:dd:dd:dd:dd:dd", "x", netip.Addr{}); ok {
		t.Fatal("Allocate handed out a fourth address from a three-address pool")
	}
}

func TestLoadRestoresLeasesAcrossARestart(t *testing.T) {
	a, _ := newTestAllocator(t)
	held := netip.MustParseAddr("192.168.1.10")
	a.Load([]Lease{{
		MAC: "aa:aa:aa:aa:aa:aa", IP: held, Hostname: "one",
		Expires: epoch.Add(12 * time.Hour),
	}})
	l, ok := a.Allocate("bb:bb:bb:bb:bb:bb", "two", netip.Addr{})
	if !ok {
		t.Fatal("Allocate refused the new client")
	}
	if l.IP == held {
		t.Fatalf("Allocate re-issued %v, which a restored lease still holds", held)
	}
}

func TestNameTaken(t *testing.T) {
	a, _ := newTestAllocator(t)
	if _, ok := a.Allocate("aa:aa:aa:aa:aa:aa", "laptop", netip.Addr{}); !ok {
		t.Fatal("Allocate refused the first client")
	}
	if !a.NameTaken("laptop", "bb:bb:bb:bb:bb:bb") {
		t.Fatal("NameTaken said laptop was free for a different MAC")
	}
	if a.NameTaken("laptop", "aa:aa:aa:aa:aa:aa") {
		t.Fatal("NameTaken said a client's own name was taken from it")
	}
	if a.NameTaken("desktop", "bb:bb:bb:bb:bb:bb") {
		t.Fatal("NameTaken said an unused name was taken")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/dhcpd/ -run 'TestAllocate|TestReservation|TestAReserved|TestQuarantined|TestDecline|TestExpired|TestExhaustion|TestLoad|TestNameTaken' -v`
Expected: FAIL to compile with `undefined: NewAllocator`.

- [ ] **Step 3: Write the implementation**

Create `internal/dhcpd/alloc.go`:

```go
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

// Reconfigure swaps the pool. Leases outside the new range are dropped: they
// name addresses this server no longer controls.
func (a *Allocator) Reconfigure(cfg Config) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cfg = cfg
	for ip, mac := range a.byIP {
		if !a.usable(ip) && a.reserved[mac] != ip {
			delete(a.byIP, ip)
			delete(a.byMAC, mac)
		}
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

	// 1. A reservation always wins, in or out of the dynamic range.
	if ip, ok := a.reserved[mac]; ok {
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
	return a.inRange(ip) && ip != a.cfg.Host && ip != a.cfg.Gateway
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
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/dhcpd/ -v`
Expected: PASS, every allocator test plus Task 4's.

- [ ] **Step 5: Check for a data race**

Run: `go test ./internal/dhcpd/ -race -count=2`
Expected: PASS. The allocator is reached from the packet handler and the UI at once, so its mutex needs to be real.

- [ ] **Step 6: Commit**

```bash
git add internal/dhcpd/alloc.go internal/dhcpd/alloc_test.go
git commit -m "feat(dhcpd): address allocation

Reservation, then renewal, then requested-IP, then lowest-free, with
quarantine, exhaustion, and first-claim-wins hostname arbitration. No
sockets and an injected clock, so every rule is directly testable."
```

---

