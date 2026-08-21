package dhcpd

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/yoshiofthewire/kydns-server/internal/store"
)

var testSubnet = netip.MustParsePrefix("192.168.1.0/24")

func TestReservationsResolvesTheUniqueInSubnetAddress(t *testing.T) {
	svcs := []store.Service{{
		Name: "kypost",
		MAC:  "aa:bb:cc:dd:ee:ff",
		Addresses: []store.Address{
			{Address: "192.168.1.20"},
			{Address: "10.9.0.20", View: "vpn"}, // outside the DHCP subnet
		},
	}}
	got, problems := Reservations(svcs, testSubnet)
	if len(problems) != 0 {
		t.Fatalf("problems = %+v, want none", problems)
	}
	if want := netip.MustParseAddr("192.168.1.20"); got["aa:bb:cc:dd:ee:ff"] != want {
		t.Fatalf("reservation = %v, want %v", got["aa:bb:cc:dd:ee:ff"], want)
	}
}

func TestReservationsIgnoresServicesWithNoMAC(t *testing.T) {
	svcs := []store.Service{{
		Name:      "kypost",
		Addresses: []store.Address{{Address: "192.168.1.20"}},
	}}
	got, problems := Reservations(svcs, testSubnet)
	if len(got) != 0 || len(problems) != 0 {
		t.Fatalf("got %+v, problems %+v; a service with no MAC is not a reservation", got, problems)
	}
}

func TestReservationWithNoInSubnetAddressIsFlagged(t *testing.T) {
	svcs := []store.Service{{
		Name:      "offsite",
		MAC:       "aa:bb:cc:dd:ee:ff",
		Addresses: []store.Address{{Address: "10.9.0.20"}},
	}}
	got, problems := Reservations(svcs, testSubnet)
	if len(got) != 0 {
		t.Fatalf("reservations = %+v, want none", got)
	}
	if len(problems) != 1 || problems[0].Service != "offsite" {
		t.Fatalf("problems = %+v, want one naming offsite", problems)
	}
	if problems[0].Reason == "" {
		t.Fatal("problem has no reason; the UI shows this to the operator verbatim")
	}
}

func TestReservationWithTwoInSubnetAddressesIsFlagged(t *testing.T) {
	svcs := []store.Service{{
		Name: "ambiguous",
		MAC:  "aa:bb:cc:dd:ee:ff",
		Addresses: []store.Address{
			{Address: "192.168.1.20"},
			{Address: "192.168.1.21"},
		},
	}}
	got, problems := Reservations(svcs, testSubnet)
	if len(got) != 0 {
		t.Fatalf("reservations = %+v, want none: which of the two would it be?", got)
	}
	if len(problems) != 1 {
		t.Fatalf("problems = %+v, want one", problems)
	}
}

func TestReservationWithTheSameAddressInTwoViewsResolves(t *testing.T) {
	// One address, offered in two views, is still one address.
	svcs := []store.Service{{
		Name: "kypost",
		MAC:  "aa:bb:cc:dd:ee:ff",
		Addresses: []store.Address{
			{Address: "192.168.1.20", View: "lan"},
			{Address: "192.168.1.20", View: "guest"},
		},
	}}
	got, problems := Reservations(svcs, testSubnet)
	if len(problems) != 0 {
		t.Fatalf("problems = %+v, want none: it is one address in two views", problems)
	}
	if want := netip.MustParseAddr("192.168.1.20"); got["aa:bb:cc:dd:ee:ff"] != want {
		t.Fatalf("reservation = %v, want %v", got["aa:bb:cc:dd:ee:ff"], want)
	}
}

func TestReservationsSkipsUnparseableAddresses(t *testing.T) {
	svcs := []store.Service{{
		Name: "kypost",
		MAC:  "aa:bb:cc:dd:ee:ff",
		Addresses: []store.Address{
			{Address: "not-an-address"},
			{Address: "192.168.1.20"},
		},
	}}
	got, problems := Reservations(svcs, testSubnet)
	if len(problems) != 0 {
		t.Fatalf("problems = %+v, want none", problems)
	}
	if want := netip.MustParseAddr("192.168.1.20"); got["aa:bb:cc:dd:ee:ff"] != want {
		t.Fatalf("reservation = %v, want %v", got["aa:bb:cc:dd:ee:ff"], want)
	}
}

// Uniqueness is enforced on write, so this is a row that predates the rule or
// was edited by hand. Reserving either service's address would hand the device
// the other one's, so neither is reserved and both are flagged.
func TestTwoServicesSharingAMACReserveNeither(t *testing.T) {
	svcs := []store.Service{
		{Name: "old", MAC: "aa:bb:cc:dd:ee:ff", Addresses: []store.Address{{Address: "192.168.1.20"}}},
		{Name: "new", MAC: "aa:bb:cc:dd:ee:ff", Addresses: []store.Address{{Address: "192.168.1.21"}}},
	}
	got, problems := Reservations(svcs, testSubnet)
	if len(got) != 0 {
		t.Fatalf("reservations = %+v, want none: the MAC names two services", got)
	}
	if len(problems) != 2 {
		t.Fatalf("problems = %+v, want both services flagged", problems)
	}
	for _, p := range problems {
		if !strings.Contains(p.Reason, "aa:bb:cc:dd:ee:ff") && p.MAC != "aa:bb:cc:dd:ee:ff" {
			t.Errorf("problem %+v does not name the shared MAC", p)
		}
	}
}
