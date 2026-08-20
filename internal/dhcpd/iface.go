// Package dhcpd is the built-in DHCPv4 server: one scope, one interface.
// It implements discovery/dhcp.Source, so the leases it hands out reach DNS
// through the path lease-file discovery already uses.
package dhcpd

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// ErrNotSupported is returned when the host cannot serve DHCP at all. Its
// message is shown to the operator, so it names the two supported
// deployments rather than the internal reason.
var ErrNotSupported = errors.New(
	"DHCP needs to hear broadcasts from clients, which this deployment cannot: " +
		"run KyDNS as a native package install, or in Docker with network_mode: host")

// IfaceInfo is everything the server and the setup wizard need to know about
// the interface DHCP will run on.
type IfaceInfo struct {
	Name          string
	Addr          netip.Addr   // our IPv4 address on this interface
	Subnet        netip.Prefix // masked
	Gateway       netip.Addr   // the host's default route; zero if there is none
	HasGlobalIPv6 bool         // evidence the segment is dual-stack
}

// Inspect reads the interface. It does not decide whether DHCP may run;
// Qualifies does that.
func Inspect(name string) (IfaceInfo, error) {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return IfaceInfo{}, fmt.Errorf("interface %q: %w", name, err)
	}
	info := IfaceInfo{Name: name}
	addrs, err := ifi.Addrs()
	if err != nil {
		return IfaceInfo{}, fmt.Errorf("interface %q addresses: %w", name, err)
	}
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		addr, ok := netip.AddrFromSlice(n.IP)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		if addr.Is4() && !info.Addr.IsValid() {
			ones, _ := n.Mask.Size()
			info.Addr = addr
			info.Subnet = netip.PrefixFrom(addr, ones).Masked()
		}
		if addr.Is6() && addr.IsGlobalUnicast() && !addr.IsPrivate() {
			info.HasGlobalIPv6 = true
		}
	}
	if !info.Addr.IsValid() {
		return IfaceInfo{}, fmt.Errorf("interface %q has no IPv4 address", name)
	}
	if gw, ok := defaultGateway(); ok {
		info.Gateway = gw
	}
	return info, nil
}

// Qualifies reports whether DHCP may run on this interface. A nil return is
// the only thing that lets the listener start.
func Qualifies(name string) error {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return fmt.Errorf("interface %q: %w", name, err)
	}
	if ifi.Flags&net.FlagUp == 0 {
		return fmt.Errorf("interface %q is down", name)
	}
	if ifi.Flags&net.FlagLoopback != 0 {
		return fmt.Errorf("interface %q is the loopback", name)
	}
	if isVeth(name) {
		// Everything above passes inside a bridge-mode container. The socket
		// would bind, and no client would ever be heard.
		return ErrNotSupported
	}
	if _, err := Inspect(name); err != nil {
		return err
	}
	return nil
}

func isVeth(name string) bool {
	b, err := os.ReadFile("/sys/class/net/" + name + "/uevent")
	if err != nil {
		return false
	}
	return ueventIsVeth(string(b))
}

// ueventIsVeth is split out so it can be tested without a sysfs.
func ueventIsVeth(uevent string) bool {
	for _, line := range strings.Split(uevent, "\n") {
		if strings.TrimSpace(line) == "DEVTYPE=veth" {
			return true
		}
	}
	return false
}

func defaultGateway() (netip.Addr, bool) {
	b, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return netip.Addr{}, false
	}
	return parseProcRoute(string(b))
}

// parseProcRoute finds the default route's gateway. Addresses in
// /proc/net/route are little-endian hex; the default route is the one whose
// destination is zero and whose flags carry RTF_GATEWAY (0x2).
func parseProcRoute(table string) (netip.Addr, bool) {
	for _, line := range strings.Split(table, "\n")[1:] {
		f := strings.Fields(line)
		if len(f) < 4 || f[1] != "00000000" {
			continue
		}
		flags, err := strconv.ParseUint(f[3], 16, 32)
		if err != nil || flags&0x2 == 0 {
			continue
		}
		raw, err := hex.DecodeString(f[2])
		if err != nil || len(raw) != 4 {
			continue
		}
		var be [4]byte
		binary.BigEndian.PutUint32(be[:], binary.LittleEndian.Uint32(raw))
		return netip.AddrFrom4(be), true
	}
	return netip.Addr{}, false
}

// SuggestRange proposes a pool: the upper half of the subnet, ending one
// below the broadcast address. The wizard shows this and the operator can
// change it, so it errs toward being obviously a suggestion rather than
// toward cleverness. It does not avoid the host's own address or the
// gateway — the allocator excludes both from allocation regardless.
func SuggestRange(subnet netip.Prefix) (start, end netip.Addr, err error) {
	if !subnet.Addr().Is4() {
		return start, end, errors.New("the DHCP range must be an IPv4 subnet")
	}
	bits := subnet.Bits()
	if bits > 29 {
		return start, end, fmt.Errorf("subnet %v is too small to hold a DHCP range", subnet)
	}
	base := subnet.Masked().Addr().As4()
	size := uint32(1) << uint(32-bits)
	network := binary.BigEndian.Uint32(base[:])

	startU := network + size/2
	endU := network + size - 2 // one below the broadcast address

	var sb, eb [4]byte
	binary.BigEndian.PutUint32(sb[:], startU)
	binary.BigEndian.PutUint32(eb[:], endU)
	return netip.AddrFrom4(sb), netip.AddrFrom4(eb), nil
}
