// Package settings owns the process configuration that lives in the database.
// It holds the live snapshot the runtime reads and the single path by which
// that snapshot changes.
package settings

import (
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"

	"github.com/miekg/dns"
	"github.com/yoshiofthewire/kydns-server/internal/store"
	"github.com/yoshiofthewire/kydns-server/internal/upstream"
)

// ErrPublicNotConfirmed is returned when allow_query would expose the
// resolver to the public internet and the caller did not confirm it.
var ErrPublicNotConfirmed = errors.New("allow_query includes a public range and was not confirmed")

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

// Validate reports whether v may be stored. Both the first-run seed and every
// later write call it, so nothing can reach the database that could not have
// been in the config file.
func Validate(v store.Settings, confirmPublic string) error {
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
	if err := validateAllowQuery(v.AllowQuery, confirmPublic); err != nil {
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

// Replaced in the next commit by the public-range guardrail.
func validateAllowQuery(list []string, _ string) error {
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
