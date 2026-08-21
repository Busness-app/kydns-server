package dhcpd

import (
	"net"
	"net/netip"
	"os"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
)

func offerFrom(serverID, offered string) *dhcpv4.DHCPv4 {
	m, err := dhcpv4.New()
	if err != nil {
		panic(err)
	}
	m.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeOffer))
	m.UpdateOption(dhcpv4.OptServerIdentifier(net.ParseIP(serverID)))
	m.YourIPAddr = net.ParseIP(offered)
	return m
}

// wire presents messages the way readReplies hands them over. These all carry
// a server identifier, so the source address is never consulted.
func wire(ms ...*dhcpv4.DHCPv4) []reply {
	out := make([]reply, 0, len(ms))
	for _, m := range ms {
		out = append(out, reply{msg: m})
	}
	return out
}

// scriptConn replays a fixed sequence of datagrams and then fails the way a
// passed deadline does. No socket is opened.
type scriptConn struct {
	net.PacketConn
	in []datagram
}

type datagram struct {
	b   []byte
	src net.Addr
}

func (c *scriptConn) ReadFrom(b []byte) (int, net.Addr, error) {
	if len(c.in) == 0 {
		return 0, nil, os.ErrDeadlineExceeded
	}
	d := c.in[0]
	c.in = c.in[1:]
	return copy(b, d.b), d.src, nil
}

// offerBytes is an OFFER as it comes off the wire, with the chaddr a server
// chose to echo back.
func offerBytes(t *testing.T, xid dhcpv4.TransactionID, chaddr net.HardwareAddr) []byte {
	t.Helper()
	m, err := dhcpv4.New()
	if err != nil {
		t.Fatalf("build offer: %v", err)
	}
	m.TransactionID = xid
	m.ClientHWAddr = chaddr
	m.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeOffer))
	m.UpdateOption(dhcpv4.OptServerIdentifier(net.IP{192, 168, 1, 1}))
	m.YourIPAddr = net.IP{192, 168, 1, 64}
	return m.ToBytes()
}

func from(ip string) net.Addr {
	return &net.UDPAddr{IP: net.IP(netip.MustParseAddr(ip).AsSlice()), Port: 67}
}

// probeChaddr stands in for the random MAC DetectForeign generates.
var probeChaddr = net.HardwareAddr{0x02, 0, 0, 0, 0, 1}

func TestCollectForeignIgnoresOurOwnOffers(t *testing.T) {
	self := netip.MustParseAddr("192.168.1.5")
	got := collectForeign(wire(offerFrom("192.168.1.5", "192.168.1.10")), self)
	if len(got) != 0 {
		t.Fatalf("collectForeign = %+v, want none: that offer is ours", got)
	}
}

func TestCollectForeignReportsAnotherServer(t *testing.T) {
	self := netip.MustParseAddr("192.168.1.5")
	got := collectForeign(wire(offerFrom("192.168.1.1", "192.168.1.64")), self)
	if len(got) != 1 {
		t.Fatalf("collectForeign = %+v, want one entry", got)
	}
	if got[0].ServerID.String() != "192.168.1.1" || got[0].Offered.String() != "192.168.1.64" {
		t.Fatalf("entry = %+v, want server 192.168.1.1 offering 192.168.1.64", got[0])
	}
}

func TestCollectForeignDedupesOneServerAnsweringTwice(t *testing.T) {
	self := netip.MustParseAddr("192.168.1.5")
	got := collectForeign(wire(
		offerFrom("192.168.1.1", "192.168.1.64"),
		offerFrom("192.168.1.1", "192.168.1.64"),
	), self)
	if len(got) != 1 {
		t.Fatalf("collectForeign = %+v, want one entry after dedupe", got)
	}
}

func TestCollectForeignIgnoresNonOffers(t *testing.T) {
	self := netip.MustParseAddr("192.168.1.5")
	ack := offerFrom("192.168.1.1", "192.168.1.64")
	ack.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeAck))
	if got := collectForeign(wire(ack), self); len(got) != 0 {
		t.Fatalf("collectForeign = %+v, want none: an ACK is not an offer of service", got)
	}
}

// A server that omits option 54 is still a server. Dropping it would report
// clear on a segment that is not.
func TestCollectForeignFallsBackToTheSourceWithoutAServerID(t *testing.T) {
	m, err := dhcpv4.New()
	if err != nil {
		t.Fatalf("build offer: %v", err)
	}
	m.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeOffer))
	m.YourIPAddr = net.IP{192, 168, 1, 64}

	got := collectForeign(
		[]reply{{msg: m, src: netip.MustParseAddr("192.168.1.1")}},
		netip.MustParseAddr("192.168.1.5"),
	)
	if len(got) != 1 {
		t.Fatalf("collectForeign = %+v, want one entry from the source address", got)
	}
	if got[0].ServerID.String() != "192.168.1.1" || got[0].Offered.String() != "192.168.1.64" {
		t.Fatalf("entry = %+v, want server 192.168.1.1 offering 192.168.1.64", got[0])
	}
}

func TestForeignStringWithoutAnOfferedAddress(t *testing.T) {
	f := Foreign{ServerID: netip.MustParseAddr("192.168.1.1")}
	if got, want := f.String(), "192.168.1.1 (offering unknown)"; got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}

// Our probe has no NIC with this MAC and no address to be unicast to, so a
// cleared broadcast flag makes every OFFER unreceivable.
func TestNewProbeDiscoveryAsksForABroadcastReply(t *testing.T) {
	m, err := newProbeDiscovery(probeChaddr)
	if err != nil {
		t.Fatalf("newProbeDiscovery: %v", err)
	}
	if !m.IsBroadcast() {
		t.Fatalf("flags = %#04x, want the broadcast bit set", m.Flags)
	}
}

// hlen is the server's choice: a server answering with hlen 0 produces a
// chaddr that never matches ours, and correlating on it drops a real OFFER.
func TestReadRepliesKeepsAnOfferWhoseChaddrDiffers(t *testing.T) {
	xid := dhcpv4.TransactionID{1, 2, 3, 4}
	conn := &scriptConn{in: []datagram{{offerBytes(t, xid, net.HardwareAddr{}), from("192.168.1.1")}}}

	got := readReplies(conn, xid)
	if len(got) != 1 {
		t.Fatalf("readReplies = %+v, want the offer kept: its transaction ID is ours", got)
	}
	if got[0].src.String() != "192.168.1.1" {
		t.Fatalf("src = %v, want 192.168.1.1", got[0].src)
	}
}

func TestReadRepliesDropsAnotherClientsOffer(t *testing.T) {
	conn := &scriptConn{in: []datagram{
		{offerBytes(t, dhcpv4.TransactionID{9, 9, 9, 9}, probeChaddr), from("192.168.1.1")},
	}}

	if got := readReplies(conn, dhcpv4.TransactionID{1, 2, 3, 4}); len(got) != 0 {
		t.Fatalf("readReplies = %+v, want none: that answers somebody else's DISCOVER", got)
	}
}

func TestReadRepliesSkipsGarbageAndKeepsReading(t *testing.T) {
	xid := dhcpv4.TransactionID{1, 2, 3, 4}
	conn := &scriptConn{in: []datagram{
		{[]byte("not a dhcp packet"), from("192.168.1.9")},
		{offerBytes(t, xid, probeChaddr), from("192.168.1.1")},
	}}

	if got := readReplies(conn, xid); len(got) != 1 {
		t.Fatalf("readReplies = %+v, want one: garbage must not end the wait", got)
	}
}

func TestReadRepliesEndsAtTheDeadline(t *testing.T) {
	if got := readReplies(&scriptConn{}, dhcpv4.TransactionID{1, 2, 3, 4}); len(got) != 0 {
		t.Fatalf("readReplies = %+v, want none", got)
	}
}
