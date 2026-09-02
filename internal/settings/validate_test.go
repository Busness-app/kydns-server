package settings

import (
	"errors"
	"strings"
	"testing"

	"github.com/Busness-app/kydns-server/internal/store"
)

// validateFresh is the write path with nothing stored yet: every prefix in v is
// new, which is how the guardrail cases below are framed.
func validateFresh(v store.Settings, confirmPublic string) error {
	return ValidateWrite(v, store.Settings{}, confirmPublic)
}

// valid is a settings value every test starts from, so each case changes
// exactly one thing and the failure names itself.
func valid() store.Settings {
	return store.Settings{
		PrivateDomain:     "home.arpa",
		ReverseZones:      []string{"192.168.1.0/24"},
		Upstreams:         []string{"tls://1.1.1.1:853"},
		AllowQuery:        []string{"192.168.0.0/16"},
		TTL:               60,
		CacheMinTTL:       5,
		CacheMaxTTL:       3600,
		NegativeMaxTTL:    300,
		CacheEntries:      10000,
		DiscoveryInterval: 30,
		HealthInterval:    30,
		HealthTimeout:     5,
		HealthWorkers:     8,
	}
}

func TestValidateAcceptsDefaults(t *testing.T) {
	if err := validateFresh(valid(), ""); err != nil {
		t.Fatalf("the shipped defaults must validate: %v", err)
	}
}

func TestValidateStoredAcceptsDefaults(t *testing.T) {
	if err := ValidateStored(valid()); err != nil {
		t.Fatalf("the shipped defaults must validate: %v", err)
	}
}

// The startup path waives the confirmation and nothing else: an ACL that was
// legal when the operator wrote it must not take their resolver offline on an
// upgrade.
func TestValidateStoredHonoursAPublicPrefix(t *testing.T) {
	v := valid()
	v.AllowQuery = []string{"192.168.0.0/16", "0.0.0.0/0"}
	if err := ValidateStored(v); err != nil {
		t.Fatalf("an already-configured public range must start: %v", err)
	}
	// The write path is unchanged: new exposure still needs confirming.
	if err := validateFresh(v, ""); err == nil {
		t.Fatal("the write-path guardrail regressed")
	}
}

// Every rule below runs through both entry points, so the two cannot drift.
func TestValidateRejects(t *testing.T) {
	cases := []struct {
		name  string
		mut   func(*store.Settings)
		field string
	}{
		{"empty private domain", func(s *store.Settings) { s.PrivateDomain = "" }, "private_domain"},
		{"private domain is not a name", func(s *store.Settings) { s.PrivateDomain = "not a domain" }, "private_domain"},
		{"unparseable reverse zone", func(s *store.Settings) { s.ReverseZones = []string{"192.168.1.0"} }, "reverse_zones"},
		{"no upstreams", func(s *store.Settings) { s.Upstreams = nil }, "upstreams"},
		{"unparseable upstream", func(s *store.Settings) { s.Upstreams = []string{"tls://example.com"} }, "upstreams"},
		{"unparseable allow_query", func(s *store.Settings) { s.AllowQuery = []string{"192.168.0.1"} }, "allow_query"},
		// Default-closed: an empty allow list refuses every query, which is a
		// server that silently stops working.
		{"empty allow_query", func(s *store.Settings) { s.AllowQuery = nil }, "allow_query"},
		{"zero ttl", func(s *store.Settings) { s.TTL = 0 }, "ttl"},
		{"min ttl above max", func(s *store.Settings) { s.CacheMinTTL = 4000 }, "cache_min_ttl"},
		{"zero cache entries", func(s *store.Settings) { s.CacheEntries = 0 }, "cache_entries"},
		{"zero negative max ttl", func(s *store.Settings) { s.NegativeMaxTTL = 0 }, "negative_max_ttl"},
		{"zero discovery interval", func(s *store.Settings) { s.DiscoveryInterval = 0 }, "discovery_interval"},
		{"no health workers", func(s *store.Settings) { s.HealthWorkers = 0 }, "health_workers"},
		// A probe that outlives its own cycle stacks up forever.
		{"health timeout not below interval", func(s *store.Settings) { s.HealthTimeout = 30 }, "health_timeout"},
	}
	paths := map[string]func(store.Settings) error{
		"ValidateWrite":  func(v store.Settings) error { return validateFresh(v, "") },
		"ValidateStored": ValidateStored,
	}
	for _, tc := range cases {
		for name, check := range paths {
			t.Run(tc.name+"/"+name, func(t *testing.T) {
				v := valid()
				tc.mut(&v)
				err := check(v)
				if err == nil {
					t.Fatal("accepted a value it must reject")
				}
				var fe FieldError
				if !errors.As(err, &fe) {
					t.Fatalf("error is not a FieldError, so no input can be highlighted: %v", err)
				}
				if fe.Field != tc.field {
					t.Errorf("blamed %q, want %q", fe.Field, tc.field)
				}
			})
		}
	}
}

// A relative lease path would resolve against whatever directory the process
// happened to start in, which differs between the host and the container.
func TestValidateRejectsRelativeLeasePath(t *testing.T) {
	v := valid()
	v.DHCPLeaseFile = "leases"
	err := validateFresh(v, "")
	if err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("relative lease path accepted: %v", err)
	}
}

// An empty lease path is how discovery stays off, and must remain valid.
func TestValidateAllowsDiscoveryOff(t *testing.T) {
	v := valid()
	v.DHCPLeaseFile = ""
	if err := validateFresh(v, ""); err != nil {
		t.Fatalf("discovery off must validate: %v", err)
	}
}

// allow_query is what stops KyDNS being an open resolver, so widening it must
// be impossible to do by accident.
func TestValidateRejectsPublicPrefixWithoutConfirmation(t *testing.T) {
	v := valid()
	v.AllowQuery = []string{"192.168.0.0/16", "0.0.0.0/0"}

	err := validateFresh(v, "")
	if err == nil {
		t.Fatal("a public range was accepted with no confirmation")
	}
	var fe FieldError
	if !errors.As(err, &fe) || fe.Field != "allow_query" {
		t.Fatalf("wrong field blamed: %v", err)
	}
	if !strings.Contains(err.Error(), "0.0.0.0/0") {
		t.Errorf("the message does not name the offending prefix: %v", err)
	}
}

// The confirmation is the prefix itself, so muscle memory cannot supply it and
// a copy-pasted API body cannot carry a blanket override.
func TestValidateAcceptsPublicPrefixWithMatchingConfirmation(t *testing.T) {
	v := valid()
	v.AllowQuery = []string{"192.168.0.0/16", "0.0.0.0/0"}
	if err := validateFresh(v, "0.0.0.0/0"); err != nil {
		t.Fatalf("a confirmed public range must be accepted: %v", err)
	}
}

func TestValidateRejectsMismatchedConfirmation(t *testing.T) {
	v := valid()
	v.AllowQuery = []string{"8.8.8.0/24"}
	if err := validateFresh(v, "0.0.0.0/0"); err == nil {
		t.Fatal("a confirmation for a different prefix was accepted")
	}
}

// Confirming one public prefix must not smuggle a second one through.
func TestValidateRejectsSecondUnconfirmedPublicPrefix(t *testing.T) {
	v := valid()
	v.AllowQuery = []string{"0.0.0.0/0", "8.8.8.0/24"}
	err := validateFresh(v, "0.0.0.0/0")
	if err == nil || !strings.Contains(err.Error(), "8.8.8.0/24") {
		t.Fatalf("the unconfirmed second prefix passed: %v", err)
	}
}

func TestPrivatePrefixesNeedNoConfirmation(t *testing.T) {
	for _, c := range []string{
		"127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12",
		"192.168.0.0/16", "169.254.0.0/16", "fe80::/10", "fc00::/7",
		"100.64.0.0/10", "192.168.1.128/25",
	} {
		v := valid()
		v.AllowQuery = []string{c}
		if err := validateFresh(v, ""); err != nil {
			t.Errorf("%s is a private range and must need no confirmation: %v", c, err)
		}
	}
}

// The guardrail gates new exposure. Re-litigating a prefix the operator already
// accepted would mean no save ever succeeds again while it is stored — and with
// two of them, no single confirmation could satisfy both.
func TestValidateWriteAgainstStoredPublicPrefixes(t *testing.T) {
	withACL := func(acl ...string) store.Settings {
		v := valid()
		v.AllowQuery = acl
		return v
	}
	cases := []struct {
		name    string
		next    store.Settings
		prev    store.Settings
		confirm string
		wantErr bool
	}{
		{
			name: "an unrelated save with one public prefix stored",
			next: func() store.Settings {
				v := withACL("192.168.0.0/16", "0.0.0.0/0")
				v.TTL = 120
				return v
			}(),
			prev: withACL("192.168.0.0/16", "0.0.0.0/0"),
		},
		{
			name: "an unrelated save with two public prefixes stored",
			next: func() store.Settings {
				v := withACL("0.0.0.0/0", "8.8.8.0/24")
				v.TTL = 120
				return v
			}(),
			prev: withACL("0.0.0.0/0", "8.8.8.0/24"),
		},
		{
			name:    "adding a public prefix unconfirmed",
			next:    withACL("192.168.0.0/16", "8.8.8.0/24"),
			prev:    withACL("192.168.0.0/16"),
			wantErr: true,
		},
		{
			name:    "adding a public prefix confirmed",
			next:    withACL("192.168.0.0/16", "8.8.8.0/24"),
			prev:    withACL("192.168.0.0/16"),
			confirm: "8.8.8.0/24",
		},
		{
			name:    "adding a second public prefix beside a stored one",
			next:    withACL("0.0.0.0/0", "8.8.8.0/24"),
			prev:    withACL("0.0.0.0/0"),
			wantErr: true,
		},
		{
			name: "removing a public prefix needs no confirmation",
			next: withACL("192.168.0.0/16"),
			prev: withACL("192.168.0.0/16", "0.0.0.0/0"),
		},
		{
			// The removal took it out of prev, so it is new again.
			name:    "re-adding a removed public prefix",
			next:    withACL("192.168.0.0/16", "0.0.0.0/0"),
			prev:    withACL("192.168.0.0/16"),
			wantErr: true,
		},
		{
			// Pre-confirmation is by canonical form, so the misleading host-bits
			// spelling of a stored prefix does not smuggle anything new in.
			name: "a stored prefix respelled with host bits",
			next: withACL("192.168.1.99/0"),
			prev: withACL("0.0.0.0/0"),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateWrite(tc.next, tc.prev, tc.confirm)
			if tc.wantErr && err == nil {
				t.Fatal("new exposure was accepted with no confirmation")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("an already-accepted exposure blocked the save: %v", err)
			}
		})
	}
}

func TestPublicPrefixes(t *testing.T) {
	got := PublicPrefixes([]string{"192.168.0.0/16", "0.0.0.0/0", "junk", "8.8.8.8/32"})
	want := []string{"0.0.0.0/0", "8.8.8.8/32"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

// A prefix with set host bits, like 192.168.1.99/0, matches as 0.0.0.0/0 but
// reads as a LAN address. The rejection must name what it actually matches.
func TestValidateRejectsHostBitsFormReportedCanonically(t *testing.T) {
	v := valid()
	v.AllowQuery = []string{"192.168.1.99/0"}

	err := validateFresh(v, "")
	if err == nil {
		t.Fatal("a /0 disguised as a LAN address was accepted with no confirmation")
	}
	if !strings.Contains(err.Error(), "0.0.0.0/0") {
		t.Errorf("the message does not name the canonical prefix: %v", err)
	}
	if strings.Contains(err.Error(), "192.168.1.99/0") {
		t.Errorf("the message must not echo the misleading host-bits form: %v", err)
	}
}

// Confirming the canonical form is what works; the raw host-bits form the
// operator typed is not itself a valid confirmation.
func TestValidateAcceptsHostBitsFormWithCanonicalConfirmation(t *testing.T) {
	v := valid()
	v.AllowQuery = []string{"192.168.1.99/0"}

	if err := validateFresh(v, "0.0.0.0/0"); err != nil {
		t.Fatalf("confirming the canonical form must be accepted: %v", err)
	}
	if err := validateFresh(v, "192.168.1.99/0"); err == nil {
		t.Fatal("confirming the raw host-bits form must not be accepted")
	}
}

// dhcpSettings is a valid DHCP configuration every DHCP test starts from.
func dhcpSettings() store.Settings {
	v := valid()
	v.DHCPEnabled = true
	v.DHCPInterface = "eth0"
	v.DHCPRangeStart = "192.168.1.128"
	v.DHCPRangeEnd = "192.168.1.254"
	v.DHCPGateway = "192.168.1.1"
	v.DHCPLeaseSeconds = 86400
	return v
}

func TestDHCPValidationAcceptsAGoodConfiguration(t *testing.T) {
	if err := ValidateStored(dhcpSettings()); err != nil {
		t.Fatalf("ValidateStored rejected a valid DHCP configuration: %v", err)
	}
}

func TestDHCPDisabledIgnoresEveryOtherField(t *testing.T) {
	v := dhcpSettings()
	v.DHCPEnabled = false
	v.DHCPInterface = ""
	v.DHCPRangeStart = "nonsense"
	if err := ValidateStored(v); err != nil {
		t.Fatalf("ValidateStored rejected a disabled DHCP configuration: %v", err)
	}
}

// The field travels to the client, which highlights the box it names. Every
// wire and CLI key is snake_case, so a dotted name points at a field nobody
// sent.
func TestDHCPValidationRejects(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*store.Settings)
		field  string
	}{
		{"no interface", func(v *store.Settings) { v.DHCPInterface = "" }, "dhcp_interface"},
		{"unparseable start", func(v *store.Settings) { v.DHCPRangeStart = "nope" }, "dhcp_range_start"},
		{"unparseable end", func(v *store.Settings) { v.DHCPRangeEnd = "nope" }, "dhcp_range_end"},
		{"ipv6 start", func(v *store.Settings) { v.DHCPRangeStart = "2001:db8::1" }, "dhcp_range_start"},
		{"end below start", func(v *store.Settings) {
			v.DHCPRangeStart, v.DHCPRangeEnd = "192.168.1.254", "192.168.1.128"
		}, "dhcp_range_end"},
		{"range larger than 65536 addresses", func(v *store.Settings) {
			v.DHCPRangeStart, v.DHCPRangeEnd = "10.0.0.1", "10.2.0.1"
		}, "dhcp_range_end"},
		{"range of 65537 addresses, one past the cap", func(v *store.Settings) {
			v.DHCPRangeStart, v.DHCPRangeEnd = "10.0.0.0", "10.1.0.0"
		}, "dhcp_range_end"},
		{"the whole IPv4 address space", func(v *store.Settings) {
			v.DHCPRangeStart, v.DHCPRangeEnd = "0.0.0.0", "255.255.255.255"
		}, "dhcp_range_end"},
		{"unparseable gateway", func(v *store.Settings) { v.DHCPGateway = "nope" }, "dhcp_gateway"},
		{"lease too short", func(v *store.Settings) { v.DHCPLeaseSeconds = 299 }, "dhcp_lease_seconds"},
		{"lease too long", func(v *store.Settings) { v.DHCPLeaseSeconds = 604801 }, "dhcp_lease_seconds"},
		{"unparseable secondary dns", func(v *store.Settings) { v.DHCPSecondaryDNS = "nope" }, "dhcp_secondary_dns"},
		{"lease file at the same time", func(v *store.Settings) { v.DHCPLeaseFile = "/var/lib/misc/dnsmasq.leases" }, "dhcp_enabled"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := dhcpSettings()
			c.mutate(&v)
			err := ValidateStored(v)
			if err == nil {
				t.Fatalf("ValidateStored accepted %s", c.name)
			}
			var fe FieldError
			if !errors.As(err, &fe) {
				t.Fatalf("error %v is not a FieldError; the form cannot highlight a field", err)
			}
			if fe.Field != c.field {
				t.Fatalf("error names field %q, want %q", fe.Field, c.field)
			}
			if strings.Contains(fe.Field, ".") {
				t.Errorf("field %q is not a key the client ever sends", fe.Field)
			}
		})
	}
}

func TestDHCPLeaseSecondsBoundariesAreInclusive(t *testing.T) {
	for _, secs := range []int{300, 604800} {
		v := dhcpSettings()
		v.DHCPLeaseSeconds = secs
		if err := ValidateStored(v); err != nil {
			t.Fatalf("ValidateStored rejected the boundary value %d: %v", secs, err)
		}
	}
}

// A pool of exactly 65536 addresses is the cap, not past it, and must be
// accepted.
func TestDHCPRangeOf65536AddressesIsAccepted(t *testing.T) {
	v := dhcpSettings()
	v.DHCPRangeStart, v.DHCPRangeEnd = "10.0.0.0", "10.0.255.255"
	if err := ValidateStored(v); err != nil {
		t.Fatalf("ValidateStored rejected a 65536-address range: %v", err)
	}
}
