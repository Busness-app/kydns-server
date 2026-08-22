package registry

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// ValidationError carries the offending field so the CLI and the UI can render
// the same failure. Code is the machine-readable form.
type ValidationError struct {
	Field   string
	Code    string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

func invalid(field, code, format string, args ...any) error {
	return &ValidationError{Field: field, Code: code, Message: fmt.Sprintf(format, args...)}
}

// Invalid builds a ValidationError. Exported so sibling services report field
// failures in the form both transports already render.
func Invalid(field, code, format string, args ...any) error {
	return invalid(field, code, format, args...)
}

// Normalize lowercases a name and gives it a trailing dot.
func Normalize(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return ""
	}
	if !strings.HasSuffix(n, ".") {
		n += "."
	}
	return n
}

// ValidateLabel applies RFC 1035 preferred-syntax rules: letters, digits, and
// interior hyphens, 1 to 63 octets.
func ValidateLabel(s string) error {
	if s == "" || len(s) > 63 {
		return invalid("name", "label_length", "label %q must be 1 to 63 characters", s)
	}
	if s[0] == '-' || s[len(s)-1] == '-' {
		return invalid("name", "label_hyphen", "label %q may not start or end with a hyphen", s)
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
		default:
			return invalid("name", "label_charset", "label %q contains an invalid character %q", s, r)
		}
	}
	return nil
}

// ValidateName checks that a normalized FQDN is a strict subdomain of the
// private zone, with every label valid and no wildcards.
func ValidateName(name, privateFQDN string) error {
	n := Normalize(name)
	if n == "" {
		return invalid("name", "name_empty", "name is required")
	}
	if len(n) > 255 {
		return invalid("name", "name_length", "name exceeds 255 characters")
	}
	if strings.Contains(n, "*") {
		return invalid("name", "wildcard_unsupported", "wildcards are not supported")
	}
	zone := Normalize(privateFQDN)
	if n == zone {
		return invalid("name", "name_is_apex", "name may not be the zone apex %q", zone)
	}
	if !strings.HasSuffix(n, "."+zone) {
		return invalid("name", "name_out_of_zone", "name %q must fall inside %q", n, zone)
	}
	for _, label := range strings.Split(strings.TrimSuffix(n, "."), ".") {
		if err := ValidateLabel(label); err != nil {
			return err
		}
	}
	return nil
}

func ValidateAddress(s string) error {
	if _, err := netip.ParseAddr(s); err != nil {
		return invalid("address", "address_invalid", "%q is not an IP address", s)
	}
	return nil
}

// NormalizeMAC is the one form a MAC is stored and compared in: lowercase,
// colon-separated, which is what net.HardwareAddr renders. Its body is
// deliberately identical to dhcpd's normalizeMAC - the two are separate only
// because registry must not import dhcpd for one string helper - so a
// reservation and a lease compare as plain strings. TestNormalizeMAC in each
// package pins the agreement.
func NormalizeMAC(s string) string {
	s = strings.TrimSpace(s)
	if hw, err := net.ParseMAC(s); err == nil {
		return hw.String()
	}
	return strings.ToLower(s)
}

// ValidateMAC accepts an empty MAC - most services have no reservation - and
// otherwise requires a 6-byte Ethernet address. Longer forms parse as MACs
// but are not something a DHCPv4 client will present.
func ValidateMAC(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	hw, err := net.ParseMAC(s)
	if err != nil {
		return invalid("mac", "malformed", "%q is not a MAC address", s)
	}
	if len(hw) != 6 {
		return invalid("mac", "malformed", "%q is not a 6-byte Ethernet MAC address", s)
	}
	return nil
}

var recordTypes = map[string]bool{"A": true, "AAAA": true, "CNAME": true, "PTR": true}

func ValidateRecordType(s string) error {
	if !recordTypes[s] {
		return invalid("type", "type_unsupported", "record type %q is not supported in v1", s)
	}
	return nil
}
