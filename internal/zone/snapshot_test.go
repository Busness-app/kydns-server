package zone

import (
	"bytes"
	"log/slog"
	"net/netip"
	"strings"
	"testing"

	"github.com/yoshiofthewire/kydns-server/internal/store"
)

func build(t *testing.T, in Input) *Snapshot {
	t.Helper()
	in.Zone = "home.arpa."
	if in.ReverseZones == nil {
		in.ReverseZones = []netip.Prefix{
			netip.MustParsePrefix("192.168.1.0/24"),
			netip.MustParsePrefix("100.64.0.0/10"),
		}
	}
	s, err := Build(in, nil)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func values(rrs []RR) []string {
	out := make([]string, 0, len(rrs))
	for _, r := range rrs {
		out = append(out, r.Value)
	}
	return out
}

func kypost() store.Service {
	return store.Service{
		ID:   1,
		Name: "kypost",
		Addresses: []store.Address{
			{Address: "192.168.1.20"},
			{Address: "100.101.102.103", View: "tailnet"},
		},
		Aliases: []string{"webmail"},
	}
}

func tailnetView() []store.View {
	return []store.View{{Name: "tailnet", Subnets: []string{"100.64.0.0/10"}}}
}

func TestViewTaggedAddressSuppressesUntagged(t *testing.T) {
	s := build(t, Input{Views: tailnetView(), Services: []store.Service{kypost()}})

	got := values(s.Lookup("tailnet", "kypost.home.arpa."))
	if len(got) != 1 || got[0] != "100.101.102.103" {
		t.Errorf("tailnet view = %v, want only the tagged address", got)
	}
	got = values(s.Lookup("", "kypost.home.arpa."))
	if len(got) != 1 || got[0] != "192.168.1.20" {
		t.Errorf("default view = %v, want only the untagged address", got)
	}
}

func TestUntaggedAddressVisibleInEveryView(t *testing.T) {
	svc := store.Service{ID: 1, Name: "nas", Addresses: []store.Address{{Address: "192.168.1.30"}}}
	s := build(t, Input{Views: tailnetView(), Services: []store.Service{svc}})
	for _, view := range []string{"", "tailnet"} {
		got := values(s.Lookup(view, "nas.home.arpa."))
		if len(got) != 1 || got[0] != "192.168.1.30" {
			t.Errorf("view %q = %v, want the untagged address", view, got)
		}
	}
}

func TestAliasResolvesToServiceAddress(t *testing.T) {
	s := build(t, Input{Views: tailnetView(), Services: []store.Service{kypost()}})
	got := values(s.Lookup("tailnet", "webmail.home.arpa."))
	if len(got) != 1 || got[0] != "100.101.102.103" {
		t.Errorf("alias in tailnet = %v, want the tagged address", got)
	}
}

func TestManualRecordBeatsService(t *testing.T) {
	s := build(t, Input{
		Services: []store.Service{kypost()},
		Records:  []store.Record{{Name: "kypost.home.arpa.", Type: "A", Value: "192.168.1.99"}},
	})
	got := values(s.Lookup("", "kypost.home.arpa."))
	if len(got) != 1 || got[0] != "192.168.1.99" {
		t.Errorf("= %v, want the manual record to win", got)
	}
}

func TestServiceBeatsLease(t *testing.T) {
	s := build(t, Input{
		Services: []store.Service{kypost()},
		Leases:   []Lease{{Hostname: "kypost", Address: "192.168.1.77"}},
	})
	got := values(s.Lookup("", "kypost.home.arpa."))
	if len(got) != 1 || got[0] != "192.168.1.20" {
		t.Errorf("= %v, want the service to win over the lease", got)
	}
}

func TestLeaseResolvesWhenUnshadowed(t *testing.T) {
	s := build(t, Input{Leases: []Lease{{Hostname: "laptop", Address: "192.168.1.77"}}})
	got := values(s.Lookup("", "laptop.home.arpa."))
	if len(got) != 1 || got[0] != "192.168.1.77" {
		t.Errorf("= %v, want the lease to resolve", got)
	}
}

// A discovered lease resolves in reverse as well as forward, so dig -x on a
// DHCP client works the same as on a service.
func TestLeaseDerivesPTR(t *testing.T) {
	s := build(t, Input{Leases: []Lease{{Hostname: "laptop", Address: "192.168.1.77"}}})
	if got := s.LookupPTR("", "77.1.168.192.in-addr.arpa."); got != "laptop.home.arpa." {
		t.Errorf("lease PTR = %q, want laptop.home.arpa.", got)
	}
}

// A service outranks a lease in reverse just as it does in forward.
func TestServicePTRBeatsLeasePTR(t *testing.T) {
	s := build(t, Input{
		Services: []store.Service{kypost()},
		Leases:   []Lease{{Hostname: "other", Address: "192.168.1.20"}},
	})
	if got := s.LookupPTR("", "20.1.168.192.in-addr.arpa."); got != "kypost.home.arpa." {
		t.Errorf("PTR = %q, want the service name to win", got)
	}
}

func TestPTRDerivedPerView(t *testing.T) {
	s := build(t, Input{Views: tailnetView(), Services: []store.Service{kypost()}})

	if got := s.LookupPTR("", "20.1.168.192.in-addr.arpa."); got != "kypost.home.arpa." {
		t.Errorf("default PTR = %q, want kypost.home.arpa.", got)
	}
	if got := s.LookupPTR("tailnet", "103.102.101.100.in-addr.arpa."); got != "kypost.home.arpa." {
		t.Errorf("tailnet PTR = %q, want kypost.home.arpa.", got)
	}
	// The tailnet address is absent from the default view entirely.
	if got := s.LookupPTR("", "103.102.101.100.in-addr.arpa."); got != "" {
		t.Errorf("default view PTR for tailnet address = %q, want empty", got)
	}
}

func TestAliasesDoNotGeneratePTR(t *testing.T) {
	s := build(t, Input{Services: []store.Service{kypost()}})
	if got := s.LookupPTR("", "20.1.168.192.in-addr.arpa."); got == "webmail.home.arpa." {
		t.Error("PTR resolved to an alias, want the service name")
	}
}

// A CNAME may not coexist with an address record at the same name. Because a
// manual record displaces the service layer, and a view-tagged record
// suppresses untagged ones, the only way both land in one view's effective set
// is two manual records sharing a name and a tag.
func TestCNAMEConflictRejected(t *testing.T) {
	for name, records := range map[string][]store.Record{
		"both untagged": {
			{Name: "mail.home.arpa.", Type: "A", Value: "192.168.1.20"},
			{Name: "mail.home.arpa.", Type: "CNAME", Value: "nas.home.arpa."},
		},
		"both tagged the same view": {
			{Name: "mail.home.arpa.", Type: "CNAME", Value: "nas.home.arpa.", View: "tailnet"},
			{Name: "mail.home.arpa.", Type: "A", Value: "100.101.102.103", View: "tailnet"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Build(Input{Zone: "home.arpa.", Views: tailnetView(), Records: records}, nil)
			if err == nil {
				t.Fatal("Build() error = nil, want a CNAME conflict")
			}
		})
	}
}

// A manual record displaces the service entry for its name, so a CNAME tagged
// to a view replaces that view's service address rather than colliding.
func TestManualCNAMEDisplacesServiceAddress(t *testing.T) {
	s := build(t, Input{
		Views:    tailnetView(),
		Services: []store.Service{kypost()},
		Records: []store.Record{
			{Name: "kypost.home.arpa.", Type: "CNAME", Value: "nas.home.arpa.", View: "tailnet"},
		},
	})
	rrs := s.Lookup("tailnet", "kypost.home.arpa.")
	if len(rrs) != 1 || rrs[0].Type != "CNAME" {
		t.Errorf("tailnet = %+v, want the CNAME alone", rrs)
	}
	// The default view is untouched by a tailnet-tagged record.
	if got := values(s.Lookup("", "kypost.home.arpa.")); len(got) != 1 || got[0] != "192.168.1.20" {
		t.Errorf("default view = %v, want the service address", got)
	}
}

// Two manual A records at one name are a multi-homed host, not a conflict:
// both must survive.
func TestMultipleManualAddressRecordsAccumulate(t *testing.T) {
	s := build(t, Input{Records: []store.Record{
		{Name: "dual.home.arpa.", Type: "A", Value: "192.168.1.10"},
		{Name: "dual.home.arpa.", Type: "A", Value: "192.168.1.11"},
	}})
	got := values(s.Lookup("", "dual.home.arpa."))
	if len(got) != 2 {
		t.Fatalf("= %v, want both addresses", got)
	}
}

func TestGenerationIsCarried(t *testing.T) {
	s := build(t, Input{Generation: 42})
	if s.Generation != 42 {
		t.Errorf("Generation = %d, want 42", s.Generation)
	}
}

// An address outside every configured reverse zone must not produce a PTR.
func TestPTROnlyInsideConfiguredReverseZones(t *testing.T) {
	s := build(t, Input{
		ReverseZones: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
		Services: []store.Service{{
			ID: 1, Name: "far", Addresses: []store.Address{{Address: "10.9.9.9"}},
		}},
	})
	if got := s.LookupPTR("", "9.9.9.10.in-addr.arpa."); got != "" {
		t.Errorf("PTR = %q for an address outside the reverse zones, want empty", got)
	}
}

func TestAAAAAddressTypedCorrectly(t *testing.T) {
	s := build(t, Input{
		ReverseZones: []netip.Prefix{netip.MustParsePrefix("fd00::/8")},
		Services: []store.Service{{
			ID: 1, Name: "six", Addresses: []store.Address{{Address: "fd00::1"}},
		}},
	})
	rrs := s.Lookup("", "six.home.arpa.")
	if len(rrs) != 1 || rrs[0].Type != "AAAA" {
		t.Errorf("= %+v, want one AAAA record", rrs)
	}
}

// A view with no tagged address for a name still sees untagged records, and an
// unknown view falls back to the default index rather than returning nothing.
func TestUnknownViewFallsBackToDefault(t *testing.T) {
	s := build(t, Input{Views: tailnetView(), Services: []store.Service{kypost()}})
	got := values(s.Lookup("does-not-exist", "kypost.home.arpa."))
	if len(got) != 1 || got[0] != "192.168.1.20" {
		t.Errorf("= %v, want the default view's answer", got)
	}
}

// The headline behaviour: clients are sent to the proxy, reverse lookups still
// name the real host.
func TestProxyRoutedServiceAnswersWithTheProxy(t *testing.T) {
	snap := build(t, Input{
		Zone:         "home.arpa.",
		ReverseZones: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
		Services: []store.Service{{
			ID: 1, Name: "kypost",
			Addresses:     []store.Address{{Address: "192.168.1.30"}},
			Aliases:       []string{"webmail"},
			ProxyAddress:  "192.168.1.20",
			RouteViaProxy: true,
		}},
	})
	idx := snap.Views[""]

	for _, name := range []string{"kypost.home.arpa.", "webmail.home.arpa."} {
		rrs := idx.Forward[name]
		if len(rrs) != 1 || rrs[0].Value != "192.168.1.20" {
			t.Errorf("%s = %v, want the proxy address", name, rrs)
		}
	}
	if got := idx.Reverse["30.1.168.192.in-addr.arpa."]; got != "kypost.home.arpa." {
		t.Errorf("reverse for the real address = %q, want kypost.home.arpa.", got)
	}
	if got := idx.Reverse["20.1.168.192.in-addr.arpa."]; got != "" {
		t.Errorf("reverse for the proxy address = %q, want none", got)
	}
}

func TestUnroutedServiceIgnoresTheProxyAddress(t *testing.T) {
	snap := build(t, Input{
		Zone: "home.arpa.",
		Services: []store.Service{{
			ID: 1, Name: "kypost",
			Addresses:    []store.Address{{Address: "192.168.1.30"}},
			ProxyAddress: "192.168.1.20", // stored, routing off
		}},
	})
	rrs := snap.Views[""].Forward["kypost.home.arpa."]
	if len(rrs) != 1 || rrs[0].Value != "192.168.1.30" {
		t.Errorf("= %v, want the real address while routing is off", rrs)
	}
}

// Routing decides what an answer says, never whether one exists.
func TestProxyDoesNotCreateAServiceInAViewItIsAbsentFrom(t *testing.T) {
	snap := build(t, Input{
		Zone:  "home.arpa.",
		Views: []store.View{{Name: "lan", Subnets: []string{"192.168.1.0/24"}}},
		Services: []store.Service{{
			ID: 1, Name: "kypost",
			Addresses:     []store.Address{{Address: "100.64.0.5", View: "tailnet"}},
			ProxyAddress:  "192.168.1.20",
			RouteViaProxy: true,
		}},
	})
	if rrs := snap.Views["lan"].Forward["kypost.home.arpa."]; len(rrs) != 0 {
		t.Errorf("lan view = %v, want nothing: the service has no lan address", rrs)
	}
}

// The bug this fixes: two services on one address silently lose a reverse
// record. Resolution stays last-writer-wins, but it must be visible.
func TestSharedAddressLogsAReverseConflict(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	if _, err := Build(Input{
		Zone:         "home.arpa.",
		ReverseZones: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
		Services: []store.Service{
			{ID: 1, Name: "a", Addresses: []store.Address{{Address: "192.168.1.30"}}},
			{ID: 2, Name: "b", Addresses: []store.Address{{Address: "192.168.1.30"}}},
		},
	}, logger); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"192.168.1.30", "a.home.arpa.", "b.home.arpa."} {
		if !strings.Contains(out, want) {
			t.Errorf("log %q does not mention %q", out, want)
		}
	}
}

// A lease and a service at the same address is one ordinary host, not a
// conflict: the service is expected to overwrite the lease's PTR, and that
// must stay silent.
func TestLeaseAndServiceSharingAnAddressLogsNothing(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	if _, err := Build(Input{
		Zone:         "home.arpa.",
		ReverseZones: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
		Leases:       []Lease{{Hostname: "other", Address: "192.168.1.30"}},
		Services: []store.Service{
			{ID: 1, Name: "nas", Addresses: []store.Address{{Address: "192.168.1.30"}}},
		},
	}, logger); err != nil {
		t.Fatal(err)
	}
	if out := buf.String(); out != "" {
		t.Errorf("log = %q, want nothing for a lease overwritten by its own service", out)
	}
}

// A multi-homed service (two addresses, one service) writes two distinct PTRs
// and must never be mistaken for two services sharing one address.
func TestMultiHomedServiceLogsNothing(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	if _, err := Build(Input{
		Zone:         "home.arpa.",
		ReverseZones: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
		Services: []store.Service{
			{ID: 1, Name: "nas", Addresses: []store.Address{
				{Address: "192.168.1.30"},
				{Address: "192.168.1.31"},
			}},
		},
	}, logger); err != nil {
		t.Fatal(err)
	}
	if out := buf.String(); out != "" {
		t.Errorf("log = %q, want nothing for one service with two addresses", out)
	}
}
