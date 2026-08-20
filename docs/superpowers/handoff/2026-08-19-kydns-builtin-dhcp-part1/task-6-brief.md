### Task 6: The conflict probe

**Files:**
- Create: `internal/dhcpd/probe.go`
- Test: `internal/dhcpd/probe_test.go`

**Interfaces:**
- Produces: `type Prober interface { InUse(ip netip.Addr) bool }`, `func NewProber(iface string, budget time.Duration) Prober`, `type nopProber struct{}` for tests and for the allocator paths that must not probe.

- [ ] **Step 1: Write the failing tests**

Create `internal/dhcpd/probe_test.go`. The ICMP path needs a network and privileges, so what is tested is the ARP-table parsing and the budget contract; the socket call itself is thin enough to read.

```go
package dhcpd

import (
	"net/netip"
	"testing"
	"time"
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
	start := time.Now()
	if (nopProber{}).InUse(netip.MustParseAddr("192.168.1.10")) {
		t.Fatal("nopProber reported an address in use")
	}
	if time.Since(start) > 10*time.Millisecond {
		t.Fatal("nopProber did I/O")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/dhcpd/ -run 'ARPTable|NopProber' -v`
Expected: FAIL to compile with `undefined: parseARPTable`.

- [ ] **Step 3: Write the implementation**

Create `internal/dhcpd/probe.go`:

```go
package dhcpd

import (
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

// Prober answers one question: is this address already in use by something we
// did not give it to? A false negative costs a duplicate address, which the
// client then declines; a false positive costs one address for ten minutes.
// The budget is small because it sits in the path of every new OFFER.
type Prober interface {
	InUse(ip netip.Addr) bool
}

// nopProber is for renewals and reservations, which are not probed, and for
// tests.
type nopProber struct{}

func (nopProber) InUse(netip.Addr) bool { return false }

type prober struct {
	iface  string
	budget time.Duration
}

// NewProber returns a Prober that checks the kernel's ARP table first and
// then, if that says nothing, sends one ICMP echo. Both share budget.
func NewProber(iface string, budget time.Duration) Prober {
	if budget <= 0 {
		budget = 100 * time.Millisecond
	}
	return &prober{iface: iface, budget: budget}
}

func (p *prober) InUse(ip netip.Addr) bool {
	deadline := time.Now().Add(p.budget)
	if b, err := os.ReadFile("/proc/net/arp"); err == nil {
		if parseARPTable(string(b), p.iface)[ip] {
			return true
		}
	}
	return icmpAnswers(ip, time.Until(deadline))
}

// parseARPTable returns the addresses on iface with a complete (ATF_COM,
// 0x2) entry. A complete entry means something answered ARP for it recently.
func parseARPTable(table, iface string) map[netip.Addr]bool {
	live := map[netip.Addr]bool{}
	lines := strings.Split(table, "\n")
	if len(lines) > 0 {
		lines = lines[1:] // drop the header row
	}
	for _, line := range lines {
		f := strings.Fields(line)
		if len(f) < 6 || f[5] != iface {
			continue
		}
		flags, err := strconv.ParseUint(strings.TrimPrefix(f[2], "0x"), 16, 32)
		if err != nil || flags&0x2 == 0 {
			continue
		}
		if addr, err := netip.ParseAddr(f[0]); err == nil {
			live[addr] = true
		}
	}
	return live
}

// icmpAnswers sends one echo request and waits for any reply. It needs an
// unprivileged ICMP socket, which Linux allows within
// net.ipv4.ping_group_range; where it is not permitted this returns false and
// the ARP check is the whole probe. That is a documented weaker check, not a
// silent one: the caller logs when the socket cannot be opened.
func icmpAnswers(ip netip.Addr, budget time.Duration) bool {
	if budget <= 0 {
		return false
	}
	c, err := net.DialTimeout("ip4:icmp", ip.String(), budget)
	if err != nil {
		return false
	}
	defer c.Close()
	if err := c.SetDeadline(time.Now().Add(budget)); err != nil {
		return false
	}
	// Echo request: type 8, code 0, id and seq zero, no payload. The checksum
	// covers an otherwise-zero header, so it is a constant.
	msg := []byte{8, 0, 0xf7, 0xff, 0, 0, 0, 0}
	if _, err := c.Write(msg); err != nil {
		return false
	}
	buf := make([]byte, 64)
	_, err = c.Read(buf)
	return err == nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/dhcpd/ -run 'ARPTable|NopProber' -v`
Expected: PASS.

- [ ] **Step 5: Confirm the ICMP path degrades rather than fails**

Run: `go test ./internal/dhcpd/ -run 'ARPTable|NopProber' -count=1 -v` as an unprivileged user (which is how it already ran).
Expected: PASS. `icmpAnswers` returns false when the socket cannot be opened, so an unprivileged environment gets the ARP check alone and no error.

- [ ] **Step 6: Commit**

```bash
git add internal/dhcpd/probe.go internal/dhcpd/probe_test.go
git commit -m "feat(dhcpd): probe an address before offering it

ARP table first, then one ICMP echo, sharing a 100ms budget. Where the
ICMP socket is not permitted the ARP check stands alone and the caller
logs the downgrade rather than pretending to a check it did not make."
```

---

