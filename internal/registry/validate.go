package registry

import (
	"fmt"
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

var recordTypes = map[string]bool{"A": true, "AAAA": true, "CNAME": true, "PTR": true}

func ValidateRecordType(s string) error {
	if !recordTypes[s] {
		return invalid("type", "type_unsupported", "record type %q is not supported in v1", s)
	}
	return nil
}
