package dhcpd

import (
	"context"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

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

// dnsmasq, ISC dhcpd and systemd-networkd all answer with option 54 set to the
// address of the interface they answered on, so a DHCP server sharing this host
// identifies itself as us. Filtering that out reports a clear segment on the
// one deployment this feature most has to get right.
func TestCollectForeignReportsAServerSharingOurAddress(t *testing.T) {
	got := collectForeign(wire(offerFrom("192.168.1.5", "192.168.1.10")))
	if len(got) != 1 {
		t.Fatalf("collectForeign = %+v, want one entry: a server on this host is still a second server", got)
	}
	if got[0].ServerID.String() != "192.168.1.5" {
		t.Fatalf("entry = %+v, want the co-resident server named", got[0])
	}
}

func TestCollectForeignReportsAnotherServer(t *testing.T) {
	got := collectForeign(wire(offerFrom("192.168.1.1", "192.168.1.64")))
	if len(got) != 1 {
		t.Fatalf("collectForeign = %+v, want one entry", got)
	}
	if got[0].ServerID.String() != "192.168.1.1" || got[0].Offered.String() != "192.168.1.64" {
		t.Fatalf("entry = %+v, want server 192.168.1.1 offering 192.168.1.64", got[0])
	}
}

func TestCollectForeignDedupesOneServerAnsweringTwice(t *testing.T) {
	got := collectForeign(wire(
		offerFrom("192.168.1.1", "192.168.1.64"),
		offerFrom("192.168.1.1", "192.168.1.64"),
	))
	if len(got) != 1 {
		t.Fatalf("collectForeign = %+v, want one entry after dedupe", got)
	}
}

func TestCollectForeignIgnoresNonOffers(t *testing.T) {
	ack := offerFrom("192.168.1.1", "192.168.1.64")
	ack.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeAck))
	if got := collectForeign(wire(ack)); len(got) != 0 {
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

	got := collectForeign([]reply{{msg: m, src: netip.MustParseAddr("192.168.1.1")}})
	if len(got) != 1 {
		t.Fatalf("collectForeign = %+v, want one entry from the source address", got)
	}
	if got[0].ServerID.String() != "192.168.1.1" || got[0].Offered.String() != "192.168.1.64" {
		t.Fatalf("entry = %+v, want server 192.168.1.1 offering 192.168.1.64", got[0])
	}
}

// An explicit 0.0.0.0 in option 54 is no more a server address than a missing
// one. Reporting "a server at 0.0.0.0" is useless at the moment the operator
// needs a name to go and turn something off.
func TestCollectForeignFallsBackToTheSourceOnAnUnspecifiedServerID(t *testing.T) {
	got := collectForeign([]reply{{
		msg: offerFrom("0.0.0.0", "192.168.1.64"),
		src: netip.MustParseAddr("192.168.1.1"),
	}})
	if len(got) != 1 || got[0].ServerID.String() != "192.168.1.1" {
		t.Fatalf("collectForeign = %+v, want the source address named as the server", got)
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
	// The serialized flags field, not the struct: bytes 10-11 of the packet are
	// what a server on the segment actually reads.
	b := m.ToBytes()
	if len(b) < 12 || b[10]&0x80 == 0 {
		t.Fatalf("flags on the wire = %#02x%02x, want the broadcast bit set", b[10], b[11])
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

// segmentConn is the segment itself, with no socket: a client message written
// to :67 reaches every DHCP server on it, and every server's reply reaches the
// probe on :68. Our own listener is one of those servers, which is the whole
// difficulty the periodic probe has to deal with.
type segmentConn struct {
	net.PacketConn
	srv *Server // us, bound and answering while the probe runs
	// other is a second DHCP server on the segment, or nil for none.
	other func(*dhcpv4.DHCPv4) *dhcpv4.DHCPv4
	in    []datagram
}

func (c *segmentConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	m, err := dhcpv4.FromBytes(b)
	if err != nil {
		return len(b), nil
	}
	if addr.(*net.UDPAddr).Port == 67 {
		c.srv.handle(c, &net.UDPAddr{IP: net.IPv4zero, Port: 68}, m)
		if c.other != nil {
			c.deliver(c.other(m))
		}
		return len(b), nil
	}
	c.deliver(m) // a server's reply, arriving at the probe socket
	return len(b), nil
}

func (c *segmentConn) deliver(m *dhcpv4.DHCPv4) {
	if m != nil {
		c.in = append(c.in, datagram{b: m.ToBytes(), src: from("192.168.1.5")})
	}
}

func (c *segmentConn) ReadFrom(b []byte) (int, net.Addr, error) {
	if len(c.in) == 0 {
		return 0, nil, os.ErrDeadlineExceeded
	}
	d := c.in[0]
	c.in = c.in[1:]
	return copy(b, d.b), d.src, nil
}

func (c *segmentConn) SetDeadline(time.Time) error { return nil }
func (c *segmentConn) Close() error                { return nil }

func (c *segmentConn) probe(t *testing.T) []Foreign {
	t.Helper()
	got, err := c.srv.probeForeignWith(context.Background(), time.Second,
		func() (net.PacketConn, error) { return c, nil })
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	return got
}

// The periodic probe runs with our own listener bound, so our own server
// answers it exactly as any other would.
func TestProbeForeignIgnoresOurOwnAnswer(t *testing.T) {
	s, _ := newTestServer(t)
	if got := (&segmentConn{srv: s}).probe(t); len(got) != 0 {
		t.Fatalf("probe = %+v on a segment whose only DHCP server is us", got)
	}
}

// The test Part 1 lacked. dnsmasq, ISC dhcpd and systemd-networkd all put the
// address of the interface they answered on in option 54, so a DHCP server
// sharing this host identifies itself as us, digit for digit. It must still be
// reported, with our own listener bound and answering the same DISCOVER.
func TestProbeForeignReportsACoResidentServerAtOurOwnAddress(t *testing.T) {
	s, _ := newTestServer(t)
	ours := s.opts.Iface.Addr
	seg := &segmentConn{srv: s, other: func(m *dhcpv4.DHCPv4) *dhcpv4.DHCPv4 {
		o := offerFrom(ours.String(), "192.168.1.200")
		o.TransactionID = m.TransactionID
		return o
	}}

	got := seg.probe(t)
	if len(got) != 1 || got[0].ServerID != ours {
		t.Fatalf("probe = %+v, want the co-resident server at %s reported", got, ours)
	}
	// Our own listener offers from the test pool, which starts at .10. Reading
	// that back here would mean the entry is our own reply wearing the other
	// server's address, and the real server would be invisible behind it.
	if got[0].Offered.String() != "192.168.1.200" {
		t.Fatalf("entry = %+v, want the address the other server offered", got[0])
	}
}
