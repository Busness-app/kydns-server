### Task 4: Interface inspection

Everything the server needs to know about the host's network, with no DHCP knowledge in it. This is also where the deployment gate lives.

**Files:**
- Create: `internal/dhcpd/iface.go`
- Test: `internal/dhcpd/iface_test.go`

**Interfaces:**
- Produces:
  - `type IfaceInfo struct { Name string; Addr netip.Addr; Subnet netip.Prefix; Gateway netip.Addr; HasGlobalIPv6 bool }`
  - `func Inspect(name string) (IfaceInfo, error)`
  - `func Qualifies(name string) error` — nil when the interface can serve DHCP, otherwise an error whose message is shown to the operator verbatim.
  - `var ErrNotSupported = errors.New(...)` for the veth case.
  - `func defaultGateway() (netip.Addr, bool)`

- [ ] **Step 1: Write the failing tests**

Create `internal/dhcpd/iface_test.go`. The parsing units are tested directly; `Inspect` against a real interface is not, because a CI machine's interfaces are not ours to depend on.

```go
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
	// 0100A8C0 is 192.168.1.1. Destination 00000000 with flag bit 0x2 (UG)
	// is the default route.
	const table = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
		"eth0\t0000FEA9\t00000000\t0001\t0\t0\t1000\t0000FFFF\t0\t0\t0\n" +
		"eth0\t00000000\t0100A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
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
		name             string
		subnet           string
		host, gw         string
		wantStart, wantEnd string
	}{
		{"typical /24", "192.168.1.0/24", "192.168.1.5", "192.168.1.1", "192.168.1.128", "192.168.1.254"},
		{"/25", "10.0.0.0/25", "10.0.0.2", "10.0.0.1", "10.0.0.64", "10.0.0.126"},
		{"host sits in the upper half", "192.168.1.0/24", "192.168.1.200", "192.168.1.1", "192.168.1.128", "192.168.1.254"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			start, end, err := SuggestRange(
				netip.MustParsePrefix(c.subnet),
				netip.MustParseAddr(c.host),
				netip.MustParseAddr(c.gw))
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
	_, _, err := SuggestRange(
		netip.MustParsePrefix("192.168.1.0/30"),
		netip.MustParseAddr("192.168.1.1"),
		netip.MustParseAddr("192.168.1.2"))
	if err == nil {
		t.Fatal("SuggestRange accepted a /30; it has no room for a pool")
	}
}
```

Note the third `SuggestRange` case: the host being inside the suggested range is not something the suggestion works around, because the operator is shown the range and can move it. What the *allocator* must never do is hand out the host's own address, and that is Task 5's job, not this one.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/dhcpd/ -v`
Expected: FAIL — the package does not exist yet (`no Go files in .../internal/dhcpd`).

- [ ] **Step 3: Write the implementation**

Create `internal/dhcpd/iface.go`:

```go
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
	Addr          netip.Addr    // our IPv4 address on this interface
	Subnet        netip.Prefix  // masked
	Gateway       netip.Addr    // the host's default route; zero if there is none
	HasGlobalIPv6 bool          // evidence the segment is dual-stack
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
// toward cleverness.
func SuggestRange(subnet netip.Prefix, host, gw netip.Addr) (start, end netip.Addr, err error) {
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
```

`host` and `gw` are accepted but unused in the body: the upper half of a subnet never contains a conventionally-placed host or gateway, and the allocator excludes them regardless. Keep them in the signature — Part 2's wizard passes them, and a later refinement that does need them should not be a signature change. Add `_ = host; _ = gw` if the linter objects.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/dhcpd/ -v`
Expected: PASS, all five test functions.

- [ ] **Step 5: Commit**

```bash
git add internal/dhcpd/iface.go internal/dhcpd/iface_test.go
git commit -m "feat(dhcpd): inspect the interface and gate on deployment

The veth check is what catches bridge-mode Docker, where every other
check passes, the socket binds happily, and no client is ever heard."
```

---

