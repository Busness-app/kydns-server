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
	l, ok := a.Allocate("aa:aa:aa:aa:aa:aa", "one", netip.Addr{}, 24*time.Hour)
	if !ok {
		t.Fatal("Allocate refused the first client on an empty pool")
	}
	if want := netip.MustParseAddr("192.168.1.10"); l.IP != want {
		t.Fatalf("first address = %v, want %v", l.IP, want)
	}
	l2, ok := a.Allocate("bb:bb:bb:bb:bb:bb", "two", netip.Addr{}, 24*time.Hour)
	if !ok {
		t.Fatal("Allocate refused the second client")
	}
	if want := netip.MustParseAddr("192.168.1.11"); l2.IP != want {
		t.Fatalf("second address = %v, want %v", l2.IP, want)
	}
}

func TestAllocateRenewsTheSameClient(t *testing.T) {
	a, now := newTestAllocator(t)
	first, _ := a.Allocate("aa:aa:aa:aa:aa:aa", "one", netip.Addr{}, 24*time.Hour)
	*now = now.Add(time.Hour)
	second, ok := a.Allocate("aa:aa:aa:aa:aa:aa", "one", netip.Addr{}, 24*time.Hour)
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
	l, ok := a.Allocate("aa:aa:aa:aa:aa:aa", "one", want, 24*time.Hour)
	if !ok {
		t.Fatal("Allocate refused a free requested address")
	}
	if l.IP != want {
		t.Fatalf("address = %v, want the requested %v", l.IP, want)
	}
}

func TestAllocateIgnoresARequestedAddressThatIsTaken(t *testing.T) {
	a, _ := newTestAllocator(t)
	taken, _ := a.Allocate("aa:aa:aa:aa:aa:aa", "one", netip.Addr{}, 24*time.Hour)
	l, ok := a.Allocate("bb:bb:bb:bb:bb:bb", "two", taken.IP, 24*time.Hour)
	if !ok {
		t.Fatal("Allocate refused the second client entirely")
	}
	if l.IP == taken.IP {
		t.Fatalf("Allocate handed %v to a second client", l.IP)
	}
}

func TestAllocateIgnoresARequestedAddressOutsideTheRange(t *testing.T) {
	a, _ := newTestAllocator(t)
	l, ok := a.Allocate("aa:aa:aa:aa:aa:aa", "one", netip.MustParseAddr("192.168.1.200"), 24*time.Hour)
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
	l, ok := a.Allocate("aa:aa:aa:aa:aa:aa", "one", netip.MustParseAddr("192.168.1.11"), 24*time.Hour)
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
	l, ok := a.Allocate("aa:aa:aa:aa:aa:aa", "one", netip.Addr{}, 24*time.Hour)
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
	l, ok := a.Allocate("aa:aa:aa:aa:aa:aa", "one", netip.Addr{}, 24*time.Hour)
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
	l, _ := a.Allocate("aa:aa:aa:aa:aa:aa", "one", netip.Addr{}, 24*time.Hour)
	if want := netip.MustParseAddr("192.168.1.11"); l.IP != want {
		t.Fatalf("address = %v, want %v while .10 is quarantined", l.IP, want)
	}

	*now = now.Add(quarantineFor + time.Second)
	a.Release("aa:aa:aa:aa:aa:aa")
	l2, _ := a.Allocate("bb:bb:bb:bb:bb:bb", "two", netip.Addr{}, 24*time.Hour)
	if want := netip.MustParseAddr("192.168.1.10"); l2.IP != want {
		t.Fatalf("address = %v, want %v once the quarantine has expired", l2.IP, want)
	}
}

func TestDeclineQuarantines(t *testing.T) {
	a, _ := newTestAllocator(t)
	l, _ := a.Allocate("aa:aa:aa:aa:aa:aa", "one", netip.Addr{}, 24*time.Hour)
	if !a.Decline("aa:aa:aa:aa:aa:aa", l.IP) {
		t.Fatal("Decline refused the client that holds the address")
	}
	l2, _ := a.Allocate("bb:bb:bb:bb:bb:bb", "two", netip.Addr{}, 24*time.Hour)
	if l2.IP == l.IP {
		t.Fatalf("Allocate re-offered %v after it was declined", l.IP)
	}
}

func TestExpiredLeasesAreReusable(t *testing.T) {
	a, now := newTestAllocator(t)
	first, _ := a.Allocate("aa:aa:aa:aa:aa:aa", "one", netip.Addr{}, 24*time.Hour)
	*now = now.Add(25 * time.Hour)
	l, ok := a.Allocate("bb:bb:bb:bb:bb:bb", "two", netip.Addr{}, 24*time.Hour)
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
		if _, ok := a.Allocate(mac, "x", netip.Addr{}, 24*time.Hour); !ok {
			t.Fatalf("Allocate refused %s while the pool still had room", mac)
		}
	}
	if _, ok := a.Allocate("dd:dd:dd:dd:dd:dd", "x", netip.Addr{}, 24*time.Hour); ok {
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
	l, ok := a.Allocate("bb:bb:bb:bb:bb:bb", "two", netip.Addr{}, 24*time.Hour)
	if !ok {
		t.Fatal("Allocate refused the new client")
	}
	if l.IP == held {
		t.Fatalf("Allocate re-issued %v, which a restored lease still holds", held)
	}
}

// First claim wins for the life of the lease, and the arbitration is part of
// the commit rather than a check the caller makes first.
func TestASecondClaimOnAHostnameGetsNoName(t *testing.T) {
	a, _ := newTestAllocator(t)
	if _, ok := a.Allocate("aa:aa:aa:aa:aa:aa", "laptop", netip.Addr{}, 24*time.Hour); !ok {
		t.Fatal("Allocate refused the first client")
	}
	l, ok := a.Allocate("bb:bb:bb:bb:bb:bb", "laptop", netip.Addr{}, 24*time.Hour)
	if !ok {
		t.Fatal("Allocate refused the second client")
	}
	if l.Hostname != "" {
		t.Fatalf("hostname = %q, want none: laptop is already claimed", l.Hostname)
	}
	if again, _ := a.Allocate("aa:aa:aa:aa:aa:aa", "laptop", netip.Addr{}, 24*time.Hour); again.Hostname != "laptop" {
		t.Fatalf("hostname = %q, want the first claimant to keep its own name", again.Hostname)
	}
	if other, _ := a.Allocate("cc:cc:cc:cc:cc:cc", "desktop", netip.Addr{}, 24*time.Hour); other.Hostname != "desktop" {
		t.Fatalf("hostname = %q, want an unused name to be granted", other.Hostname)
	}
}

func TestAReservedGatewayFallsBackToADynamicAddress(t *testing.T) {
	a, _ := newTestAllocator(t)
	cfg := testConfig()
	a.SetReservations(map[string]netip.Addr{"aa:aa:aa:aa:aa:aa": cfg.Gateway})
	l, ok := a.Allocate("aa:aa:aa:aa:aa:aa", "one", netip.Addr{}, 24*time.Hour)
	if !ok {
		t.Fatal("Allocate refused the client entirely")
	}
	if l.IP == cfg.Gateway {
		t.Fatalf("Allocate handed out the gateway %v because a reservation named it", l.IP)
	}
	if want := netip.MustParseAddr("192.168.1.10"); l.IP != want {
		t.Fatalf("address = %v, want the dynamic fallback %v", l.IP, want)
	}
}

func TestAReservedHostFallsBackToADynamicAddress(t *testing.T) {
	a, _ := newTestAllocator(t)
	cfg := testConfig()
	a.SetReservations(map[string]netip.Addr{"aa:aa:aa:aa:aa:aa": cfg.Host})
	l, ok := a.Allocate("aa:aa:aa:aa:aa:aa", "one", netip.Addr{}, 24*time.Hour)
	if !ok {
		t.Fatal("Allocate refused the client entirely")
	}
	if l.IP == cfg.Host {
		t.Fatalf("Allocate handed out our own address %v because a reservation named it", l.IP)
	}
	if want := netip.MustParseAddr("192.168.1.10"); l.IP != want {
		t.Fatalf("address = %v, want the dynamic fallback %v", l.IP, want)
	}
}

func TestAReservationAddedLaterMovesTheClientsAddress(t *testing.T) {
	a, _ := newTestAllocator(t)
	first, ok := a.Allocate("aa:aa:aa:aa:aa:aa", "one", netip.Addr{}, 24*time.Hour)
	if !ok {
		t.Fatal("Allocate refused the first client")
	}
	reserved := netip.MustParseAddr("192.168.1.20") // deliberately outside the range
	a.SetReservations(map[string]netip.Addr{"aa:aa:aa:aa:aa:aa": reserved})
	moved, ok := a.Allocate("aa:aa:aa:aa:aa:aa", "one", netip.Addr{}, 24*time.Hour)
	if !ok {
		t.Fatal("Allocate refused the reserved client")
	}
	if moved.IP != reserved {
		t.Fatalf("address = %v, want the newly reserved %v", moved.IP, reserved)
	}

	// The vacated address must be genuinely free, not just unreachable through
	// this MAC: a different client can take it, and byMAC/byIP must agree.
	other, ok := a.Allocate("bb:bb:bb:bb:bb:bb", "two", netip.Addr{}, 24*time.Hour)
	if !ok {
		t.Fatal("Allocate refused a second client after the first moved")
	}
	if other.IP != first.IP {
		t.Fatalf("vacated address = %v, want the second client to get %v", other.IP, first.IP)
	}
	for _, l := range a.Leases() {
		if l.MAC == "aa:aa:aa:aa:aa:aa" && l.IP != reserved {
			t.Fatalf("Leases still lists the old address %v for the moved client", l.IP)
		}
	}
}

func TestAReservationStealsAnAddressFromAnotherClientsLease(t *testing.T) {
	a, _ := newTestAllocator(t)
	victim, ok := a.Allocate("aa:aa:aa:aa:aa:aa", "one", netip.Addr{}, 24*time.Hour)
	if !ok {
		t.Fatal("Allocate refused the first client")
	}
	a.SetReservations(map[string]netip.Addr{"bb:bb:bb:bb:bb:bb": victim.IP})
	thief, ok := a.Allocate("bb:bb:bb:bb:bb:bb", "two", netip.Addr{}, 24*time.Hour)
	if !ok {
		t.Fatal("Allocate refused the reserved client")
	}
	if thief.IP != victim.IP {
		t.Fatalf("address = %v, want the reserved %v taken from the other client", thief.IP, victim.IP)
	}

	// The original holder must be gone from both indexes, not just orphaned:
	// it should no longer show up in Leases, and a fresh Allocate for it must
	// not be treated as a renewal of the address it just lost.
	for _, l := range a.Leases() {
		if l.MAC == "aa:aa:aa:aa:aa:aa" {
			t.Fatalf("Leases still lists the client whose address was stolen: %+v", l)
		}
	}
	again, ok := a.Allocate("aa:aa:aa:aa:aa:aa", "one", netip.Addr{}, 24*time.Hour)
	if !ok {
		t.Fatal("Allocate refused the dispossessed client entirely")
	}
	if again.IP == victim.IP {
		t.Fatalf("Allocate renewed %v for the dispossessed client, but it now belongs to another MAC", again.IP)
	}
}

func TestOfferNeverWeakensALiveLease(t *testing.T) {
	a, now := newTestAllocator(t)
	l, _ := a.Allocate("aa:aa:aa:aa:aa:aa", "laptop", netip.Addr{}, 30*time.Second)

	// A hold longer than what is left extends it, and keeps the name.
	got, _, ok := a.Offer("aa:aa:aa:aa:aa:aa", netip.Addr{}, time.Minute)
	if !ok || got.IP != l.IP || got.Hostname != "laptop" {
		t.Fatalf("Offer = %+v (ok=%v), want %v still named laptop", got, ok, l.IP)
	}
	if want := epoch.Add(time.Minute); !got.Expires.Equal(want) {
		t.Fatalf("expiry = %v, want %v", got.Expires, want)
	}
	// A shorter one does not move it back.
	got, _, _ = a.Offer("aa:aa:aa:aa:aa:aa", netip.Addr{}, time.Second)
	if want := epoch.Add(time.Minute); !got.Expires.Equal(want) {
		t.Fatalf("expiry = %v, want %v: a hold never shortens a lease", got.Expires, want)
	}
	// Once the lease has expired there is nothing left to preserve.
	*now = epoch.Add(2 * time.Minute)
	got, _, _ = a.Offer("aa:aa:aa:aa:aa:aa", netip.Addr{}, time.Minute)
	if got.Hostname != "" {
		t.Fatalf("hostname = %q, want none: an expired lease is not one the client holds", got.Hostname)
	}
}

// Only the allocator knows which rule fired, and only rules 3 and 4 produce
// an address the client does not already hold. The server probes on that.
func TestOfferReportsWhetherTheAddressIsNewToTheClient(t *testing.T) {
	a, _ := newTestAllocator(t)
	const mac = "aa:aa:aa:aa:aa:aa"

	// 4. Lowest free address in the range.
	l, fresh, ok := a.Offer(mac, netip.Addr{}, time.Minute)
	if !ok || !fresh {
		t.Fatalf("Offer = %+v (fresh=%v, ok=%v), want a fresh pick", l, fresh, ok)
	}
	// 2. Renewing what the client already holds.
	if _, fresh, _ = a.Offer(mac, netip.Addr{}, time.Minute); fresh {
		t.Fatal("a renewal reported fresh; the client already holds that address")
	}
	// 3. A requested address that is free.
	req := netip.MustParseAddr("192.168.1.12")
	l, fresh, ok = a.Offer("bb:bb:bb:bb:bb:bb", req, time.Minute)
	if !ok || l.IP != req || !fresh {
		t.Fatalf("Offer = %+v (fresh=%v, ok=%v), want a fresh %v", l, fresh, ok, req)
	}
	// 1. A reservation.
	res := netip.MustParseAddr("192.168.1.11")
	a.SetReservations(map[string]netip.Addr{"cc:cc:cc:cc:cc:cc": res})
	l, fresh, ok = a.Offer("cc:cc:cc:cc:cc:cc", netip.Addr{}, time.Minute)
	if !ok || l.IP != res {
		t.Fatalf("Offer = %+v (ok=%v), want the reserved %v", l, ok, res)
	}
	if fresh {
		t.Fatal("a reservation reported fresh; it is the client's address already")
	}
}
