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

func TestAReservedGatewayFallsBackToADynamicAddress(t *testing.T) {
	a, _ := newTestAllocator(t)
	cfg := testConfig()
	a.SetReservations(map[string]netip.Addr{"aa:aa:aa:aa:aa:aa": cfg.Gateway})
	l, ok := a.Allocate("aa:aa:aa:aa:aa:aa", "one", netip.Addr{})
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
	l, ok := a.Allocate("aa:aa:aa:aa:aa:aa", "one", netip.Addr{})
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
	first, ok := a.Allocate("aa:aa:aa:aa:aa:aa", "one", netip.Addr{})
	if !ok {
		t.Fatal("Allocate refused the first client")
	}
	reserved := netip.MustParseAddr("192.168.1.20") // deliberately outside the range
	a.SetReservations(map[string]netip.Addr{"aa:aa:aa:aa:aa:aa": reserved})
	moved, ok := a.Allocate("aa:aa:aa:aa:aa:aa", "one", netip.Addr{})
	if !ok {
		t.Fatal("Allocate refused the reserved client")
	}
	if moved.IP != reserved {
		t.Fatalf("address = %v, want the newly reserved %v", moved.IP, reserved)
	}

	// The vacated address must be genuinely free, not just unreachable through
	// this MAC: a different client can take it, and byMAC/byIP must agree.
	other, ok := a.Allocate("bb:bb:bb:bb:bb:bb", "two", netip.Addr{})
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
	victim, ok := a.Allocate("aa:aa:aa:aa:aa:aa", "one", netip.Addr{})
	if !ok {
		t.Fatal("Allocate refused the first client")
	}
	a.SetReservations(map[string]netip.Addr{"bb:bb:bb:bb:bb:bb": victim.IP})
	thief, ok := a.Allocate("bb:bb:bb:bb:bb:bb", "two", netip.Addr{})
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
	again, ok := a.Allocate("aa:aa:aa:aa:aa:aa", "one", netip.Addr{})
	if !ok {
		t.Fatal("Allocate refused the dispossessed client entirely")
	}
	if again.IP == victim.IP {
		t.Fatalf("Allocate renewed %v for the dispossessed client, but it now belongs to another MAC", again.IP)
	}
}
