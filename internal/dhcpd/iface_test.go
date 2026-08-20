package dhcpd

import (
	"net/netip"
	"testing"
)

func TestIsVethReadsDevtype(t *testing.T) {
	cases := []struct {
		name   string
		uevent string
		want   bool
	}{
		{"docker bridge veth", "INTERFACE=eth0\nIFINDEX=12\nDEVTYPE=veth\n", true},
		{"physical nic", "INTERFACE=enp3s0\nIFINDEX=2\n", false},
		{"bridge", "INTERFACE=br0\nIFINDEX=3\nDEVTYPE=bridge\n", false},
		{"devtype as a substring of something else", "INTERFACE=x\nNOTDEVTYPE=veth\n", false},
		{"empty", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ueventIsVeth(c.uevent); got != c.want {
				t.Fatalf("ueventIsVeth(%q) = %v, want %v", c.uevent, got, c.want)
			}
		})
	}
}

func TestParseDefaultGateway(t *testing.T) {
	// /proc/net/route, tab-separated, addresses little-endian hex.
	// 0101A8C0 is 192.168.1.1. Destination 00000000 with flag bit 0x2 (UG)
	// is the default route.
	const table = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
		"eth0\t0000FEA9\t00000000\t0001\t0\t0\t1000\t0000FFFF\t0\t0\t0\n" +
		"eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
	got, ok := parseProcRoute(table)
	if !ok {
		t.Fatal("parseProcRoute found no default route")
	}
	if want := netip.MustParseAddr("192.168.1.1"); got != want {
		t.Fatalf("gateway = %v, want %v", got, want)
	}
}

func TestParseDefaultGatewayWithNoDefaultRoute(t *testing.T) {
	const table = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
		"eth0\t0000FEA9\t00000000\t0001\t0\t0\t1000\t0000FFFF\t0\t0\t0\n"
	if _, ok := parseProcRoute(table); ok {
		t.Fatal("parseProcRoute claimed a default route where there is none")
	}
}

func TestSuggestRangeTakesTheUpperHalf(t *testing.T) {
	cases := []struct {
		name               string
		subnet             string
		wantStart, wantEnd string
	}{
		{"typical /24", "192.168.1.0/24", "192.168.1.128", "192.168.1.254"},
		{"/25", "10.0.0.0/25", "10.0.0.64", "10.0.0.126"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			start, end, err := SuggestRange(netip.MustParsePrefix(c.subnet))
			if err != nil {
				t.Fatalf("SuggestRange: %v", err)
			}
			if start.String() != c.wantStart || end.String() != c.wantEnd {
				t.Fatalf("range = %v-%v, want %v-%v", start, end, c.wantStart, c.wantEnd)
			}
		})
	}
}

func TestSuggestRangeRefusesATinySubnet(t *testing.T) {
	// A /30 has two usable addresses. There is no range to suggest.
	_, _, err := SuggestRange(netip.MustParsePrefix("192.168.1.0/30"))
	if err == nil {
		t.Fatal("SuggestRange accepted a /30; it has no room for a pool")
	}
}
