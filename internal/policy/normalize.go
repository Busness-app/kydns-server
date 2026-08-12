// Package policy decides whether a forwarded name is blocked. It never sees
// authoritative names: the DNS pipeline consults it only after the
// authoritative lookup declines, so a local service cannot be blackholed.
package policy

import (
	"errors"
	"net/netip"
	"strings"

	"golang.org/x/net/idna"
)

// maxName and maxLabel are the DNS wire limits in presentation form, without
// the trailing dot.
const (
	maxName  = 253
	maxLabel = 63
)

var errNotADomain = errors.New("not a domain name")

// Normalize returns the canonical form of a domain: lower case, no trailing
// dot, IDNA converted to ASCII. Anything that is not a usable domain name is
// rejected rather than silently coerced, so a typo in a rule fails loudly
// instead of matching nothing forever.
func Normalize(name string) (string, error) {
	n := strings.ToLower(strings.TrimSpace(name))
	n = strings.TrimSuffix(n, ".")
	if n == "" {
		return "", errNotADomain
	}
	if _, err := netip.ParseAddr(n); err == nil {
		return "", errNotADomain // an IP address is not a name to block
	}
	n, err := idna.Lookup.ToASCII(n)
	if err != nil {
		return "", errNotADomain
	}
	if len(n) > maxName || !strings.Contains(n, ".") {
		return "", errNotADomain
	}
	for _, label := range strings.Split(n, ".") {
		if err := validLabel(label); err != nil {
			return "", err
		}
	}
	return n, nil
}

func validLabel(s string) error {
	if s == "" || len(s) > maxLabel {
		return errNotADomain
	}
	if s[0] == '-' || s[len(s)-1] == '-' {
		return errNotADomain
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-':
		default:
			return errNotADomain
		}
	}
	return nil
}
