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
		{"discovery.interval", v.DiscoveryInterval},
		{"health.interval", v.HealthInterval},
		{"health.timeout", v.HealthTimeout},
		{"health.workers", v.HealthWorkers},
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
		return bad("health.timeout", "must be below health.interval (%d), or probes outlive their own cycle", v.HealthInterval)
	}
	if v.DHCPLeaseFile != "" && !filepath.IsAbs(v.DHCPLeaseFile) {
		return bad("discovery.dhcp_lease_file", "must be an absolute path")
	}
	return nil
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
