package dhcp

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

// DnsmasqSource reads the dnsmasq lease file, whose format is:
//
//	<expiry unix> <mac> <ip> <hostname> <client-id>
type DnsmasqSource struct {
	Path string
	Now  func() time.Time

	lastSkipped []string
}

func (d *DnsmasqSource) Name() string { return "dnsmasq:" + d.Path }

// Leases reads and parses the file. Skip reasons are dropped here; the poller
// logs them via ParseDnsmasq when it wants the detail.
func (d *DnsmasqSource) Leases(ctx context.Context) ([]Lease, error) {
	f, err := os.Open(d.Path)
	if err != nil {
		return nil, fmt.Errorf("read dnsmasq leases: %w", err)
	}
	defer f.Close()
	now := time.Now
	if d.Now != nil {
		now = d.Now
	}
	leases, skipped := ParseDnsmasq(f, now())
	d.lastSkipped = skipped
	return leases, nil
}

// Skipped returns the reasons from the most recent parse, for logging.
func (d *DnsmasqSource) Skipped() []string { return d.lastSkipped }

// validLabel mirrors the registry's RFC 1035 rule. Discovery skips anything
// that fails rather than rewriting it: a silently mangled name is worse than
// an absent one, because the operator cannot tell what happened.
func validLabel(s string) bool {
	if s == "" || len(s) > 63 || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
		default:
			return false
		}
	}
	return true
}

// ParseDnsmasq returns the live, valid leases plus a human-readable reason for
// every line it dropped. The reasons are logged by the caller, so an operator
// can tell why a device is missing. Output order is stable, which the poller's
// change digest relies on.
func ParseDnsmasq(r io.Reader, now time.Time) ([]Lease, []string) {
	var skipped []string
	newest := map[string]Lease{} // hostname -> winning lease
	var order []string

	sc := bufio.NewScanner(r)
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		fields := strings.Fields(text)
		if len(fields) < 4 {
			skipped = append(skipped, fmt.Sprintf("line %d: expected at least 4 fields, got %d", line, len(fields)))
			continue
		}
		epoch, err := strconv.ParseInt(fields[0], 10, 64)
		if err != nil {
			skipped = append(skipped, fmt.Sprintf("line %d: bad expiry %q", line, fields[0]))
			continue
		}
		expires := time.Unix(epoch, 0)
		// dnsmasq writes 0 for an infinite lease.
		if epoch != 0 && !expires.After(now) {
			skipped = append(skipped, fmt.Sprintf("line %d: lease for %q expired", line, fields[3]))
			continue
		}
		addr, err := netip.ParseAddr(fields[2])
		if err != nil {
			skipped = append(skipped, fmt.Sprintf("line %d: %q is not an IP address", line, fields[2]))
			continue
		}
		host := strings.ToLower(fields[3])
		if host == "*" {
			continue // dnsmasq's marker for "no hostname supplied"
		}
		if !validLabel(host) {
			skipped = append(skipped, fmt.Sprintf("line %d: hostname %q is not a valid DNS label", line, fields[3]))
			continue
		}
		lease := Lease{MAC: fields[1], IP: addr.String(), Hostname: host, Expires: expires}

		if prev, dup := newest[host]; dup {
			skipped = append(skipped, fmt.Sprintf(
				"line %d: hostname %q claimed by %s and %s; the newer lease wins",
				line, host, prev.MAC, lease.MAC))
			if !lease.Expires.After(prev.Expires) {
				continue
			}
		} else {
			order = append(order, host)
		}
		newest[host] = lease
	}
	if err := sc.Err(); err != nil {
		skipped = append(skipped, "read error: "+err.Error())
	}

	out := make([]Lease, 0, len(order))
	for _, h := range order {
		out = append(out, newest[h])
	}
	return out, skipped
}

var _ Source = (*DnsmasqSource)(nil)
