package dhcpd

import (
	"net/netip"
	"testing"
)

func TestParseARPTable(t *testing.T) {
	// /proc/net/arp. Flags 0x2 is ATF_COM, a complete entry; 0x0 is
	// incomplete and means the address did not answer.
	const table = "IP address       HW type     Flags       HW address            Mask     Device\n" +
		"192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0\n" +
		"192.168.1.50     0x1         0x0         00:00:00:00:00:00     *        eth0\n"
	live := parseARPTable(table, "eth0")
	if !live[netip.MustParseAddr("192.168.1.1")] {
		t.Fatal("complete ARP entry was not treated as in use")
	}
	if live[netip.MustParseAddr("192.168.1.50")] {
		t.Fatal("incomplete ARP entry was treated as in use")
	}
}

func TestParseARPTableIgnoresOtherInterfaces(t *testing.T) {
	const table = "IP address       HW type     Flags       HW address            Mask     Device\n" +
		"192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        wlan0\n"
	if parseARPTable(table, "eth0")[netip.MustParseAddr("192.168.1.1")] {
		t.Fatal("an entry on another interface was counted")
	}
}

func TestNopProberNeverBlocks(t *testing.T) {
	if (nopProber{}).InUse(netip.MustParseAddr("192.168.1.10")) {
		t.Fatal("nopProber reported an address in use")
	}
}
