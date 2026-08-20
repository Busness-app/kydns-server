### Task 9: Settings validation

**Files:**
- Modify: `internal/settings/validate.go`
- Test: `internal/settings/validate_test.go`

**Interfaces:**
- Consumes: `store.Settings` DHCP fields (Task 2).
- Produces: `ValidateStored` rejects a bad DHCP configuration with a `FieldError` naming the offending key.

- [ ] **Step 1: Write the failing tests**

Add to `internal/settings/validate_test.go`. `validSettings()` is the existing helper that returns a settings value the tests mutate — reuse it.

```go
func dhcpSettings() store.Settings {
	v := validSettings()
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

func TestDHCPValidationRejects(t *testing.T) {
	cases := []struct {
		name  string
		mutate func(*store.Settings)
		field string
	}{
		{"no interface", func(v *store.Settings) { v.DHCPInterface = "" }, "dhcp.interface"},
		{"unparseable start", func(v *store.Settings) { v.DHCPRangeStart = "nope" }, "dhcp.range_start"},
		{"unparseable end", func(v *store.Settings) { v.DHCPRangeEnd = "nope" }, "dhcp.range_end"},
		{"ipv6 start", func(v *store.Settings) { v.DHCPRangeStart = "2001:db8::1" }, "dhcp.range_start"},
		{"end below start", func(v *store.Settings) {
			v.DHCPRangeStart, v.DHCPRangeEnd = "192.168.1.254", "192.168.1.128"
		}, "dhcp.range_end"},
		{"end in another subnet", func(v *store.Settings) { v.DHCPRangeEnd = "10.0.0.5" }, "dhcp.range_end"},
		{"unparseable gateway", func(v *store.Settings) { v.DHCPGateway = "nope" }, "dhcp.gateway"},
		{"lease too short", func(v *store.Settings) { v.DHCPLeaseSeconds = 299 }, "dhcp.lease_seconds"},
		{"lease too long", func(v *store.Settings) { v.DHCPLeaseSeconds = 604801 }, "dhcp.lease_seconds"},
		{"unparseable secondary dns", func(v *store.Settings) { v.DHCPSecondaryDNS = "nope" }, "dhcp.secondary_dns"},
		{"lease file at the same time", func(v *store.Settings) { v.DHCPLeaseFile = "/var/lib/misc/dnsmasq.leases" }, "dhcp.enabled"},
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
```

Add `"errors"` to the test file's imports if it is not already there.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/settings/ -run DHCP -v`
Expected: FAIL — `ValidateStored accepted no interface`, and so on.

- [ ] **Step 3: Write the implementation**

Add to `internal/settings/validate.go`, and call it from `ValidateStored` just before its final `return nil`:

```go
	if err := validateDHCP(v); err != nil {
		return err
	}
```

```go
// dhcpLeaseMin and dhcpLeaseMax bound the lease time. The floor keeps a
// misconfiguration from turning into a broadcast storm; the ceiling is a
// week, past which a lease outlives most of the reasons to have one.
const (
	dhcpLeaseMin = 300
	dhcpLeaseMax = 604800
)

// validateDHCP checks the built-in server's configuration. Every rule is
// skipped when it is off, so an operator can leave a half-filled form behind
// without it blocking every unrelated save.
//
// What is deliberately not checked here: whether the interface exists, is up,
// or can serve DHCP. That is a property of the host at this moment, not of
// the stored value, and dhcpd.Qualifies reports it where the operator can act
// on it.
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
```

The "end in another subnet" case is caught by `end.Less(start)` only when the other subnet is numerically lower. Add the explicit check after the `Less` comparison:

```go
	// A range must sit inside one subnet, and the /24 the start implies is
	// the closest thing to that available without reading the interface.
	if start.As4()[0] != end.As4()[0] || start.As4()[1] != end.As4()[1] || start.As4()[2] != end.As4()[2] {
		return bad("dhcp.range_end", "%s is not in the same /24 as the range start %s", end, start)
	}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/settings/... -v`
Expected: PASS, including every pre-existing settings test.

- [ ] **Step 5: Commit**

```bash
git add internal/settings/validate.go internal/settings/validate_test.go
git commit -m "feat(settings): validate the built-in DHCP configuration

Every rule is skipped when DHCP is off, so a half-filled form does not
block unrelated saves. Whether the interface can actually serve DHCP is
deliberately not checked here: that is a property of the host right now,
not of the stored value."
```

---

