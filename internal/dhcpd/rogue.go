package dhcpd

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"net/netip"
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
	offered := "unknown"
	if f.Offered.IsValid() {
		offered = f.Offered.String()
	}
	return fmt.Sprintf("%s (offering %s)", f.ServerID, offered)
}

// DetectForeign broadcasts a DISCOVER from a random locally-administered MAC
// and collects every OFFER that comes back. A positive result is what refuses
// to start the listener: two DHCP servers on one segment breaks the network,
// not one name.
//
// Nothing is filtered as "ours". The probe runs only when our own listener is
// not bound, and dnsmasq, ISC dhcpd and systemd-networkd all set option 54 to
// the address of the interface they answered on — so a server sharing this
// host answers with our address, and a self filter here would hide exactly the
// co-resident server an operator is most likely to have.
func DetectForeign(ctx context.Context, iface string, wait time.Duration) ([]Foreign, error) {
	mac, err := probeMAC()
	if err != nil {
		return nil, fmt.Errorf("probe mac: %w", err)
	}
	discover, err := newProbeDiscovery(mac)
	if err != nil {
		return nil, fmt.Errorf("probe packet: %w", err)
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
		return nil, fmt.Errorf("probe deadline: %w", err)
	}
	if _, err := conn.WriteTo(discover.ToBytes(), &net.UDPAddr{IP: net.IPv4bcast, Port: 67}); err != nil {
		return nil, fmt.Errorf("probe send: %w", err)
	}

	return collectForeign(readReplies(conn, discover.TransactionID)), nil
}

// newProbeDiscovery builds the probe DISCOVER. The broadcast flag is not
// optional: the probe MAC belongs to no NIC here and we hold no address, so
// an OFFER unicast to yiaddr/chaddr — what a cleared flag asks for, and what
// ISC dhcpd and dnsmasq do — could never reach us.
func newProbeDiscovery(mac net.HardwareAddr) (*dhcpv4.DHCPv4, error) {
	return dhcpv4.NewDiscovery(mac, dhcpv4.WithBroadcast(true))
}

// reply is one datagram that answered the probe, kept with the address it
// came from.
type reply struct {
	msg *dhcpv4.DHCPv4
	src netip.Addr
}

// readReplies drains the socket until its deadline, keeping the answers to
// our own DISCOVER. The transaction ID is the correlator RFC 2131 requires a
// server to echo; chaddr is not, because FromBytes truncates it to whatever
// hlen the server chose to send.
func readReplies(conn net.PacketConn, xid dhcpv4.TransactionID) []reply {
	var out []reply
	buf := make([]byte, 1500)
	for {
		n, src, err := conn.ReadFrom(buf)
		if err != nil {
			return out // deadline; that is the whole wait
		}
		m, err := dhcpv4.FromBytes(buf[:n])
		if err != nil || m.TransactionID != xid {
			continue // unreadable, or an answer to somebody else's DISCOVER
		}
		var from netip.Addr
		if u, ok := src.(*net.UDPAddr); ok {
			from = u.AddrPort().Addr().Unmap()
		}
		out = append(out, reply{msg: m, src: from})
	}
}

// bindToDevice returns a net.ListenConfig.Control func that binds the probe
// socket to iface (SO_BINDTODEVICE) so the DISCOVER leaves on the segment
// being checked, not whatever the default route picks. SO_REUSEADDR lets the
// bind succeed in cases a host DHCP client on :68 would otherwise refuse; it
// promises nothing about which socket a unicast datagram then reaches.
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
// network. Only OFFERs count, one entry per server.
func collectForeign(replies []reply) []Foreign {
	seen := map[netip.Addr]bool{}
	var out []Foreign
	for _, r := range replies {
		if r.msg.MessageType() != dhcpv4.MessageTypeOffer {
			continue
		}
		id, ok := netip.AddrFromSlice(r.msg.ServerIdentifier())
		if id = id.Unmap(); !ok || id.IsUnspecified() {
			// No usable option 54: an answer is still proof of a server, and
			// naming its source beats reporting one at 0.0.0.0.
			id = r.src
		}
		if !id.IsValid() || seen[id] {
			continue
		}
		offered, _ := netip.AddrFromSlice(r.msg.YourIPAddr)
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
