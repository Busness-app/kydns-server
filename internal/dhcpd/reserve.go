package dhcpd

import (
	"fmt"
	"net/netip"

	"github.com/yoshiofthewire/kydns-server/internal/store"
)

// ReservationProblem is a reservation that cannot be resolved. Reason is
// shown to the operator verbatim, so it says what to do rather than what
// went wrong.
type ReservationProblem struct {
	Service string
	MAC     string
	Reason  string
}

// Reservations resolves services into MAC-to-address reservations.
//
// The reserved address is the service's unique address inside the DHCP
// subnet. That one rule is what lets per-view addresses exist without a
// second concept: a service answering differently on the LAN and over a VPN
// has exactly one LAN address, and that is the one DHCP can reserve. Zero or
// more than one, and the reservation is inactive and reported - never
// guessed at, because guessing here hands a device the wrong address.
func Reservations(svcs []store.Service, subnet netip.Prefix) (map[string]netip.Addr, []ReservationProblem) {
	// Counted first so both halves of a shared MAC are flagged, whichever
	// order the rows come back in.
	claims := map[string]int{}
	for _, svc := range svcs {
		if svc.MAC != "" {
			claims[svc.MAC]++
		}
	}
	out := map[string]netip.Addr{}
	var problems []ReservationProblem
	flag := func(svc store.Service, reason string) {
		problems = append(problems, ReservationProblem{Service: svc.Name, MAC: svc.MAC, Reason: reason})
	}
	for _, svc := range svcs {
		if svc.MAC == "" {
			continue
		}
		if claims[svc.MAC] > 1 {
			// Uniqueness is enforced on write, so this is a row that predates
			// the rule or was edited by hand.
			flag(svc, fmt.Sprintf(
				"%d services claim the MAC %s; remove it from all but one to activate the reservation",
				claims[svc.MAC], svc.MAC))
			continue
		}
		seen := map[netip.Addr]bool{}
		for _, a := range svc.Addresses {
			addr, err := netip.ParseAddr(a.Address)
			if err != nil {
				continue // the registry validated these; a bad one is not this code's problem
			}
			if subnet.Contains(addr.Unmap()) {
				seen[addr.Unmap()] = true
			}
		}
		switch len(seen) {
		case 1:
			for addr := range seen {
				out[svc.MAC] = addr
			}
		case 0:
			flag(svc, fmt.Sprintf(
				"no address inside the DHCP subnet %s; give it one to activate the reservation", subnet))
		default:
			flag(svc, fmt.Sprintf(
				"%d addresses inside the DHCP subnet %s; a reservation needs exactly one", len(seen), subnet))
		}
	}
	return out, problems
}
