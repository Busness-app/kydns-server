package dhcpd

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"golang.org/x/sys/unix"
)

// Foreign is one other DHCP server that answered a probe.
type Foreign struct {
	ServerID netip.Addr
	Offered  netip.Addr
}

func (f Foreign) String() string {
	return fmt.Sprintf("%s (offering %s)", f.ServerID, f.Offered)
}

// DetectForeign broadcasts a DISCOVER from a random locally-administered MAC
// and collects OFFERs from anyone that is not us. A positive result is what
// refuses to start the listener: two DHCP servers on one segment breaks the
// network, not one name.
func DetectForeign(ctx context.Context, iface string, wait time.Duration, self netip.Addr) ([]Foreign, error) {
	mac, err := probeMAC()
	if err != nil {
		return nil, err
	}
	discover, err := dhcpv4.NewDiscovery(mac)
	if err != nil {
		return nil, err
	}

	// Bound to iface: an unbound socket leaves on the default route's
	// interface, which would probe the wrong segment on a multi-homed host —
	// exactly the case this feature exists for.
	lc := net.ListenConfig{Control: bindToDevice(iface)}
	conn, err := lc.ListenPacket(ctx, "udp4", ":68")
	if err != nil {
		return nil, fmt.Errorf("probe socket: %w", err)
	}
	defer conn.Close()

	deadline := time.Now().Add(wait)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if _, err := conn.WriteTo(discover.ToBytes(), &net.UDPAddr{IP: net.IPv4bcast, Port: 67}); err != nil {
		return nil, fmt.Errorf("probe send: %w", err)
	}

	var replies []*dhcpv4.DHCPv4
	buf := make([]byte, 1500)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			break // deadline; that is the whole wait
		}
		m, err := dhcpv4.FromBytes(buf[:n])
		if err != nil {
			continue
		}
		if !strings.EqualFold(m.ClientHWAddr.String(), mac.String()) {
			continue // an answer to somebody else's DISCOVER
		}
		replies = append(replies, m)
	}
	return collectForeign(replies, self), nil
}

// bindToDevice returns a net.ListenConfig.Control func that binds the probe
// socket to iface (SO_BINDTODEVICE) so the DISCOVER leaves on the segment
// being checked, not whatever the default route picks. SO_REUSEADDR is cheap
// insurance against a host DHCP client already holding :68.
func bindToDevice(iface string) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			if serr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface); serr != nil {
				return
			}
			serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
		})
		if err != nil {
			return err
		}
		return serr
	}
}

// collectForeign is the decision, split out so it is testable without a
// network. Only OFFERs count, and only from a server identifier that is not
// ours.
func collectForeign(replies []*dhcpv4.DHCPv4, self netip.Addr) []Foreign {
	seen := map[netip.Addr]bool{}
	var out []Foreign
	for _, m := range replies {
		if m.MessageType() != dhcpv4.MessageTypeOffer {
			continue
		}
		id, ok := netip.AddrFromSlice(m.ServerIdentifier())
		if !ok {
			continue
		}
		id = id.Unmap()
		if !id.IsValid() || id == self || seen[id] {
			continue
		}
		offered, _ := netip.AddrFromSlice(m.YourIPAddr)
		seen[id] = true
		out = append(out, Foreign{ServerID: id, Offered: offered.Unmap()})
	}
	return out
}

// probeMAC returns a random locally-administered unicast MAC, so the probe
// cannot be mistaken for a real client and cannot collide with one.
func probeMAC() (net.HardwareAddr, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	b[0] = (b[0] | 0x02) &^ 0x01 // locally administered, unicast
	return net.HardwareAddr(b), nil
}
