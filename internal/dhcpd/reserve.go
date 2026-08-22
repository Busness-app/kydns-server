package dhcpd

import (
	"fmt"
	"net"
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

// claim is one service's bid for a reservation. A bid cannot be judged until
// every other bid has been read, and the problems still have to come out in
// service order, so each one is resolved in place.
type claim struct {
	name string
	mac  string
	addr netip.Addr
	why  string
}

// Reservations resolves services into MAC-to-address reservations.
//
// The reserved address is the service's unique address inside the DHCP
// subnet. That one rule is what lets per-view addresses exist without a
// second concept: a service answering differently on the LAN and over a VPN
// has exactly one LAN address, and that is the one DHCP can reserve. Zero or
// more than one, and the reservation is inactive and reported - never
// guessed at, because guessing here hands a device the wrong address.
//
// The pairing must be one-to-one in both directions. The registry enforces
// that a MAC names one service; nothing enforces that an address does. Either
// collision is inactive and reported rather than picked between.
func Reservations(svcs []store.Service, subnet netip.Prefix) (map[string]netip.Addr, []ReservationProblem) {
	claims := make([]claim, 0, len(svcs))
	byMAC := map[string]int{}
	for _, svc := range svcs {
		// Normalized at ingest: the wire looks a client up by normalizeMAC,
		// and the replica path applies a snapshot without validating it, so a
		// legacy or hand-edited spelling would otherwise dodge the duplicate
		// rule and then never match the device it names.
		mac := normalizeMAC(svc.MAC)
		if mac == "" {
			continue
		}
		c := claim{name: svc.Name, mac: mac}
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
				c.addr = addr
			}
			if c.addr == subnet.Masked().Addr() || c.addr == broadcastOf(subnet) {
				c.why = fmt.Sprintf(
					"%s is the network or broadcast address of %s, which no device may be given; give the service another address",
					c.addr, subnet)
			}
		case 0:
			c.why = fmt.Sprintf(
				"no address inside the DHCP subnet %s; give it one to activate the reservation", subnet)
		default:
			c.why = fmt.Sprintf(
				"%d addresses inside the DHCP subnet %s; a reservation needs exactly one", len(seen), subnet)
		}
		claims = append(claims, c)
		byMAC[mac]++
	}
	// Addresses are counted only over the claims still standing: one the MAC
	// rule already disabled reserves nothing, so it contests nothing.
	byAddr := map[netip.Addr]int{}
	for i := range claims {
		c := &claims[i]
		if byMAC[c.mac] > 1 {
			// Uniqueness is enforced on write, so this is a row that predates
			// the rule or was edited by hand. It outranks any address problem:
			// the MAC is what has to be fixed first.
			c.why = fmt.Sprintf(
				"%d services claim the MAC %s; remove it from all but one to activate the reservation",
				byMAC[c.mac], c.mac)
			continue
		}
		if c.why == "" {
			byAddr[c.addr]++
		}
	}
	out := map[string]netip.Addr{}
	var problems []ReservationProblem
	for _, c := range claims {
		if c.why == "" && byAddr[c.addr] > 1 {
			// Reserving for both hands two devices one address: the second
			// client's lease evicts the first while it is still using it.
			c.why = fmt.Sprintf(
				"%d services claim the address %s; give each its own to activate the reservation",
				byAddr[c.addr], c.addr)
		}
		if c.why == "" {
			out[c.mac] = c.addr
			continue
		}
		problems = append(problems, ReservationProblem{Service: c.name, MAC: c.mac, Reason: c.why})
	}
	return out, problems
}

// broadcastOf is the last address of an IPv4 subnet. Neither it nor the
// network address may be handed to a device, but subnet.Contains accepts both
// and the allocator's protected set covers only the host and the gateway - so
// without this a service given one would have it reserved and handed out.
func broadcastOf(p netip.Prefix) netip.Addr {
	if !p.Addr().Is4() {
		return netip.Addr{}
	}
	b := p.Masked().Addr().As4()
	for i, m := range net.CIDRMask(p.Bits(), 32) {
		b[i] |= ^m
	}
	return netip.AddrFrom4(b)
}
