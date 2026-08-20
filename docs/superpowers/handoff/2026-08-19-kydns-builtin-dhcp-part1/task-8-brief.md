### Task 8: Rogue-server detection

**Files:**
- Create: `internal/dhcpd/rogue.go`
- Test: `internal/dhcpd/rogue_test.go`

**Interfaces:**
- Produces: `type Foreign struct { ServerID netip.Addr; Offered netip.Addr }`, `func DetectForeign(ctx context.Context, iface string, wait time.Duration, self netip.Addr) ([]Foreign, error)`, and the testable core `func collectForeign(replies []*dhcpv4.DHCPv4, self netip.Addr) []Foreign`.

- [ ] **Step 1: Write the failing tests**

Create `internal/dhcpd/rogue_test.go`:

```go
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/dhcpd/ -run Foreign -v`
Expected: FAIL to compile with `undefined: collectForeign`.

- [ ] **Step 3: Write the implementation**

Create `internal/dhcpd/rogue.go`:

```go
package dhcpd

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
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

	conn, err := net.ListenPacket("udp4", ":68")
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
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/dhcpd/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/dhcpd/rogue.go internal/dhcpd/rogue_test.go
git commit -m "feat(dhcpd): detect another DHCP server before binding

A DISCOVER from a random locally-administered MAC, and any OFFER whose
server identifier is not ours refuses the start. The decision is split
from the socket so it is tested without a network."
```

---

