// Package settings owns the process configuration that lives in the database.
// It holds the live snapshot the runtime reads and the single path by which
// that snapshot changes.
package settings

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"

	"github.com/miekg/dns"
	"github.com/yoshiofthewire/kydns-server/internal/store"
	"github.com/yoshiofthewire/kydns-server/internal/upstream"
)

// FieldError names the input that was wrong, so the API and the form both
// report the same field rather than a wall of prose.
type FieldError struct {
	Field string
	Msg   string
}

func (e FieldError) Error() string { return e.Field + ": " + e.Msg }

func bad(field, format string, args ...any) error {
	return FieldError{Field: field, Msg: fmt.Sprintf(format, args...)}
}

// ValidateWrite is the write path: every rule, plus the guardrail that exposure
// beyond the private ranges must be confirmed by retyping it in confirmPublic.
// Only exposure that is new relative to prev needs confirming — re-litigating a
// prefix the operator already accepted would block every unrelated save.
func ValidateWrite(next, prev store.Settings, confirmPublic string) error {
	if err := ValidateStored(next); err != nil {
		return err
	}
	return confirmPublicPrefixes(next.AllowQuery, prev.AllowQuery, confirmPublic)
}

// ValidateStored is the startup path: every rule Validate applies except the
// public-prefix confirmation, so an ACL that is already configured is honoured
// and warned about rather than refused on an upgrade.
func ValidateStored(v store.Settings) error {
	if strings.TrimSpace(v.PrivateDomain) == "" {
		return bad("private_domain", "must not be empty")
	}
	if !validDomainName(v.PrivateDomain) {
		return bad("private_domain", "%q is not a valid domain name", v.PrivateDomain)
	}
	for _, z := range v.ReverseZones {
		if _, err := netip.ParsePrefix(z); err != nil {
			return bad("reverse_zones", "%q is not a CIDR prefix", z)
		}
	}
	if len(v.Upstreams) == 0 {
		return bad("upstreams", "at least one upstream is required")
	}
	if _, err := upstream.ParseAll(v.Upstreams); err != nil {
		return bad("upstreams", "%s", err)
	}
	if err := validateAllowQuery(v.AllowQuery); err != nil {
		return err
	}
	positives := []struct {
		field string
		val   int
	}{
		{"ttl", v.TTL},
		{"cache_min_ttl", v.CacheMinTTL},
		{"cache_max_ttl", v.CacheMaxTTL},
		{"negative_max_ttl", v.NegativeMaxTTL},
		{"cache_entries", v.CacheEntries},
		{"discovery_interval", v.DiscoveryInterval},
		{"health_interval", v.HealthInterval},
		{"health_timeout", v.HealthTimeout},
		{"health_workers", v.HealthWorkers},
	}
	for _, p := range positives {
		if p.val < 1 {
			return bad(p.field, "must be at least 1")
		}
	}
	if v.CacheMinTTL > v.CacheMaxTTL {
		return bad("cache_min_ttl", "must not exceed cache_max_ttl (%d)", v.CacheMaxTTL)
	}
	if v.HealthTimeout >= v.HealthInterval {
		return bad("health_timeout", "must be below health_interval (%d), or probes outlive their own cycle", v.HealthInterval)
	}
	if v.DHCPLeaseFile != "" && !filepath.IsAbs(v.DHCPLeaseFile) {
		return bad("dhcp_lease_file", "must be an absolute path")
	}
	if err := validateDHCP(v); err != nil {
		return err
	}
	return nil
}

// dhcpLeaseMin and dhcpLeaseMax bound the lease time. The floor keeps a
// misconfiguration from turning into a broadcast storm; the ceiling is a
// week, past which a lease outlives most of the reasons to have one.
const (
	dhcpLeaseMin = 300
	dhcpLeaseMax = 604800

	// dhcpMaxPoolSize bounds how many addresses a range may span. The lease
	// table is sized to the range, so an unbounded pool is an unbounded
	// table; a /16 worth of leases is far more than a homelab segment needs.
	dhcpMaxPoolSize = 65536
)

// validateDHCP checks the built-in server's configuration. Every rule is
// skipped when it is off, so an operator can leave a half-filled form behind
// without it blocking every unrelated save.
//
// What is deliberately not checked here: whether the interface exists, is up,
// or can serve DHCP, and whether the range falls inside the interface's
// subnet. Those are properties of the host at this moment, not of the stored
// value — the same settings row must validate identically on every node.
// Task 10 owns the subnet-containment check, because it is the only place
// that holds both the stored range and the live interface.
func validateDHCP(v store.Settings) error {
	if !v.DHCPEnabled {
		return nil
	}
	if v.DHCPLeaseFile != "" {
		return bad("dhcp.enabled",
			"the built-in DHCP server and dhcp_lease_file cannot both be on; clear dhcp_lease_file first")
	}
	if strings.TrimSpace(v.DHCPInterface) == "" {
		return bad("dhcp.interface", "an interface is required to serve DHCP")
	}
	start, err := parseIPv4("dhcp.range_start", v.DHCPRangeStart)
	if err != nil {
		return err
	}
	end, err := parseIPv4("dhcp.range_end", v.DHCPRangeEnd)
	if err != nil {
		return err
	}
	if end.Less(start) {
		return bad("dhcp.range_end", "%s is below the range start %s", end, start)
	}
	// The lease table is bounded by the range size, so cap the pool rather
	// than requiring one /24: SuggestRange can propose a range that spans
	// two /24s on anything wider than a /23, and that is legitimate.
	size := be32(end.As4()) - be32(start.As4()) + 1
	if size > dhcpMaxPoolSize {
		return bad("dhcp.range_end", "the range holds %d addresses, more than the %d-address limit", size, dhcpMaxPoolSize)
	}
	if _, err := parseIPv4("dhcp.gateway", v.DHCPGateway); err != nil {
		return err
	}
	if v.DHCPSecondaryDNS != "" {
		if _, err := parseIPv4("dhcp.secondary_dns", v.DHCPSecondaryDNS); err != nil {
			return err
		}
	}
	if v.DHCPLeaseSeconds < dhcpLeaseMin || v.DHCPLeaseSeconds > dhcpLeaseMax {
		return bad("dhcp.lease_seconds", "must be between %d and %d seconds", dhcpLeaseMin, dhcpLeaseMax)
	}
	return nil
}

// be32 reads a 4-byte address as a big-endian uint32, so range sizes can be
// computed with plain arithmetic.
func be32(b [4]byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func parseIPv4(field, s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return netip.Addr{}, bad(field, "%q is not an IP address", s)
	}
	if !a.Is4() {
		return netip.Addr{}, bad(field, "%q is not an IPv4 address; the built-in DHCP server is IPv4 only", s)
	}
	return a, nil
}

// validDomainName rejects what dns.IsDomainName lets through: it only checks
// label lengths, not characters, so "not a domain" passes it.
func validDomainName(s string) bool {
	if _, ok := dns.IsDomainName(s); !ok {
		return false
	}
	for _, label := range dns.SplitDomainName(s) {
		if label == "" || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, r := range label {
			if r != '-' && !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') && !(r >= '0' && r <= '9') {
				return false
			}
		}
	}
	return true
}

// privateRanges are the prefixes a homelab resolver is expected to serve:
// loopback, RFC1918, link-local, ULA, and the CGNAT range Tailscale uses.
var privateRanges = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("100.64.0.0/10"),
}

// IsPrivatePrefix reports whether p is wholly inside a range a homelab
// resolver is expected to serve. Containment, not overlap: 0.0.0.0/0 overlaps
// every private range without being one.
func IsPrivatePrefix(p netip.Prefix) bool {
	p = p.Masked()
	for _, r := range privateRanges {
		if r.Bits() <= p.Bits() && r.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

// PublicPrefixes returns the masked, canonical form of the entries in an
// allow list that reach beyond the private ranges. Masking matters: a form
// like "192.168.1.99/0" behaves as 0.0.0.0/0 but reads as a LAN address, and
// the operator must see what the prefix actually matches. Unparseable
// entries are skipped: Validate rejects those with a better message.
// Callers use this for the standing exposure warning.
func PublicPrefixes(list []string) []string {
	var out []string
	for _, c := range list {
		p, err := netip.ParsePrefix(c)
		if err != nil || IsPrivatePrefix(p) {
			continue
		}
		out = append(out, p.Masked().String())
	}
	return out
}

// Canonicalize returns v with every prefix in its masked, canonical form. Both
// write paths — Service.Set and the first-run seed — go through it, so what an
// operator reads back is always what the ACL enforces.
func Canonicalize(v store.Settings) store.Settings {
	v.AllowQuery = canonicalPrefixes(v.AllowQuery)
	v.ReverseZones = canonicalPrefixes(v.ReverseZones)
	return v
}

// canonicalPrefixes returns each entry in its masked, canonical CIDR form,
// preserving order and length. Every entry has already passed validation by
// the time Canonicalize is called, so a parse failure cannot happen in
// practice; an entry that still fails to parse is kept as-is rather than
// silently dropped.
func canonicalPrefixes(list []string) []string {
	out := make([]string, len(list))
	for i, c := range list {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			out[i] = c
			continue
		}
		out[i] = p.Masked().String()
	}
	return out
}

// validateAllowQuery holds the rules both paths apply: the list must be
// non-empty, because an empty one refuses every query, and every entry must
// parse.
func validateAllowQuery(list []string) error {
	if len(list) == 0 {
		return bad("allow_query", "must list at least one range, or every query is refused")
	}
	for _, c := range list {
		if _, err := netip.ParsePrefix(c); err != nil {
			return bad("allow_query", "%q is not a CIDR prefix", c)
		}
	}
	return nil
}

// confirmPublicPrefixes enforces the guardrail: a prefix outside the private
// ranges is refused unless the same request retypes it in confirmPublic.
// Prefixes already present in prev are pre-confirmed, so narrowing the list or
// changing an unrelated setting never asks again. Re-adding a removed prefix
// does, because by then it is no longer in prev.
func confirmPublicPrefixes(list, prev []string, confirmPublic string) error {
	stored := make(map[string]bool)
	for _, c := range PublicPrefixes(prev) {
		stored[c] = true
	}
	for _, c := range PublicPrefixes(list) {
		if c == confirmPublic || stored[c] {
			continue
		}
		return bad("allow_query",
			"%s reaches beyond your LAN and would make KyDNS an open resolver. "+
				"Retype it in the confirmation field to allow it anyway.", c)
	}
	return nil
}
