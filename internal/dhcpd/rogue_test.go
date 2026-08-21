package dhcpd

import (
	"net"
	"net/netip"
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

func TestCollectForeignIgnoresOurOwnOffers(t *testing.T) {
	self := netip.MustParseAddr("192.168.1.5")
	got := collectForeign([]*dhcpv4.DHCPv4{offerFrom("192.168.1.5", "192.168.1.10")}, self)
	if len(got) != 0 {
		t.Fatalf("collectForeign = %+v, want none: that offer is ours", got)
	}
}

func TestCollectForeignReportsAnotherServer(t *testing.T) {
	self := netip.MustParseAddr("192.168.1.5")
	got := collectForeign([]*dhcpv4.DHCPv4{offerFrom("192.168.1.1", "192.168.1.64")}, self)
	if len(got) != 1 {
		t.Fatalf("collectForeign = %+v, want one entry", got)
	}
	if got[0].ServerID.String() != "192.168.1.1" || got[0].Offered.String() != "192.168.1.64" {
		t.Fatalf("entry = %+v, want server 192.168.1.1 offering 192.168.1.64", got[0])
	}
}

func TestCollectForeignDedupesOneServerAnsweringTwice(t *testing.T) {
	self := netip.MustParseAddr("192.168.1.5")
	got := collectForeign([]*dhcpv4.DHCPv4{
		offerFrom("192.168.1.1", "192.168.1.64"),
		offerFrom("192.168.1.1", "192.168.1.64"),
	}, self)
	if len(got) != 1 {
		t.Fatalf("collectForeign = %+v, want one entry after dedupe", got)
	}
}

func TestCollectForeignIgnoresNonOffers(t *testing.T) {
	self := netip.MustParseAddr("192.168.1.5")
	ack := offerFrom("192.168.1.1", "192.168.1.64")
	ack.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeAck))
	if got := collectForeign([]*dhcpv4.DHCPv4{ack}, self); len(got) != 0 {
		t.Fatalf("collectForeign = %+v, want none: an ACK is not an offer of service", got)
	}
}
