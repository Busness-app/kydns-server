package dnsserver

import (
	"net/netip"
	"sync"
	"testing"

	"github.com/Busness-app/kydns-server/internal/store"
	"github.com/Busness-app/kydns-server/internal/zone"
	"github.com/miekg/dns"
)

func testSnap(t *testing.T) *zone.Snapshot {
	t.Helper()
	s, err := zone.Build(zone.Input{
		Zone:         "home.arpa.",
		Generation:   7,
		ReverseZones: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
		Views:        []store.View{{Name: "tailnet", Subnets: []string{"100.64.0.0/10"}}},
		Services: []store.Service{{
			ID: 1, Name: "kypost",
			Addresses: []store.Address{
				{Address: "192.168.1.20"},
				{Address: "100.101.102.103", View: "tailnet"},
			},
			Aliases: []string{"webmail"},
		}},
		Records: []store.Record{
			{Name: "mail.home.arpa.", Type: "CNAME", Value: "kypost.home.arpa."},
			{Name: "out.home.arpa.", Type: "CNAME", Value: "example.com."},
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func authority() *Authoritative {
	return NewAuthoritative("home.arpa.", 60, []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")})
}

func ask(t *testing.T, view, name string, qtype uint16) *dns.Msg {
	t.Helper()
	return authority().Answer(testSnap(t), view, dns.Question{
		Name: name, Qtype: qtype, Qclass: dns.ClassINET,
	})
}

func TestAnswerReturnsNilOutsideZone(t *testing.T) {
	if m := ask(t, "", "example.com.", dns.TypeA); m != nil {
		t.Fatalf("Answer() = %v for an out-of-zone name, want nil", m)
	}
}

func TestAnswerSplitHorizon(t *testing.T) {
	m := ask(t, "", "kypost.home.arpa.", dns.TypeA)
	if len(m.Answer) != 1 || m.Answer[0].(*dns.A).A.String() != "192.168.1.20" {
		t.Fatalf("default view answer = %v", m.Answer)
	}
	if !m.Authoritative {
		t.Error("AA bit not set on an authoritative answer")
	}
	m = ask(t, "tailnet", "kypost.home.arpa.", dns.TypeA)
	if len(m.Answer) != 1 || m.Answer[0].(*dns.A).A.String() != "100.101.102.103" {
		t.Fatalf("tailnet answer = %v", m.Answer)
	}
}

func TestAnswerNODATA(t *testing.T) {
	m := ask(t, "", "kypost.home.arpa.", dns.TypeAAAA)
	if m.Rcode != dns.RcodeSuccess {
		t.Errorf("Rcode = %s, want NOERROR", dns.RcodeToString[m.Rcode])
	}
	if len(m.Answer) != 0 {
		t.Errorf("Answer = %v, want empty for NODATA", m.Answer)
	}
	if len(m.Ns) != 1 {
		t.Fatalf("Ns = %v, want one SOA", m.Ns)
	}
	if _, ok := m.Ns[0].(*dns.SOA); !ok {
		t.Errorf("Ns[0] = %T, want *dns.SOA", m.Ns[0])
	}
}

func TestAnswerNXDOMAIN(t *testing.T) {
	m := ask(t, "", "nope.home.arpa.", dns.TypeA)
	if m.Rcode != dns.RcodeNameError {
		t.Errorf("Rcode = %s, want NXDOMAIN", dns.RcodeToString[m.Rcode])
	}
	if len(m.Ns) != 1 {
		t.Errorf("Ns = %v, want one SOA", m.Ns)
	}
}

func TestCNAMEChasedInZone(t *testing.T) {
	m := ask(t, "", "mail.home.arpa.", dns.TypeA)
	if len(m.Answer) != 2 {
		t.Fatalf("Answer = %v, want CNAME plus the chased A", m.Answer)
	}
	if _, ok := m.Answer[0].(*dns.CNAME); !ok {
		t.Errorf("Answer[0] = %T, want *dns.CNAME", m.Answer[0])
	}
	if a, ok := m.Answer[1].(*dns.A); !ok || a.A.String() != "192.168.1.20" {
		t.Errorf("Answer[1] = %v, want the chased A record", m.Answer[1])
	}
}

func TestCNAMEOutOfZoneNotChased(t *testing.T) {
	m := ask(t, "", "out.home.arpa.", dns.TypeA)
	if len(m.Answer) != 1 {
		t.Fatalf("Answer = %v, want the CNAME alone", m.Answer)
	}
	if _, ok := m.Answer[0].(*dns.CNAME); !ok {
		t.Errorf("Answer[0] = %T, want *dns.CNAME", m.Answer[0])
	}
}

// Asking for the CNAME itself returns just the CNAME, with no chase.
func TestCNAMEQueryTypeNotChased(t *testing.T) {
	m := ask(t, "", "mail.home.arpa.", dns.TypeCNAME)
	if len(m.Answer) != 1 {
		t.Fatalf("Answer = %v, want the CNAME alone for a CNAME query", m.Answer)
	}
}

func TestSOASerialIsGeneration(t *testing.T) {
	m := ask(t, "", "nope.home.arpa.", dns.TypeA)
	soa := m.Ns[0].(*dns.SOA)
	if soa.Serial != 7 {
		t.Errorf("SOA serial = %d, want the snapshot generation 7", soa.Serial)
	}
}

func TestApexSOAAndNS(t *testing.T) {
	m := ask(t, "", "home.arpa.", dns.TypeSOA)
	if len(m.Answer) != 1 {
		t.Fatalf("SOA query answer = %v", m.Answer)
	}
	m = ask(t, "", "home.arpa.", dns.TypeNS)
	if len(m.Answer) != 1 {
		t.Fatalf("NS query answer = %v", m.Answer)
	}
	if ns, ok := m.Answer[0].(*dns.NS); !ok || ns.Ns != "ns.home.arpa." {
		t.Errorf("NS = %v, want ns.home.arpa.", m.Answer[0])
	}
}

// An unsupported type at the apex is NODATA, not a crash.
func TestApexOtherTypeIsNODATA(t *testing.T) {
	m := ask(t, "", "home.arpa.", dns.TypeMX)
	if m.Rcode != dns.RcodeSuccess || len(m.Answer) != 0 || len(m.Ns) != 1 {
		t.Errorf("apex MX = rcode %s answer %v ns %v, want NODATA with SOA",
			dns.RcodeToString[m.Rcode], m.Answer, m.Ns)
	}
}

func TestReversePerView(t *testing.T) {
	m := ask(t, "", "20.1.168.192.in-addr.arpa.", dns.TypePTR)
	if len(m.Answer) != 1 {
		t.Fatalf("PTR answer = %v", m.Answer)
	}
	if p := m.Answer[0].(*dns.PTR); p.Ptr != "kypost.home.arpa." {
		t.Errorf("PTR = %q, want kypost.home.arpa.", p.Ptr)
	}
}

// A reverse name inside a configured zone with no record is NXDOMAIN.
func TestReverseInZoneWithoutRecordIsNXDOMAIN(t *testing.T) {
	m := ask(t, "", "99.1.168.192.in-addr.arpa.", dns.TypePTR)
	if m == nil {
		t.Fatal("Answer() = nil for a name inside a configured reverse zone")
	}
	if m.Rcode != dns.RcodeNameError {
		t.Errorf("Rcode = %s, want NXDOMAIN", dns.RcodeToString[m.Rcode])
	}
}

// An .arpa name outside every configured reverse zone is not ours: it must
// return nil so the pipeline forwards it rather than answering NXDOMAIN.
func TestUnconfiguredReverseZoneNotOwned(t *testing.T) {
	if m := ask(t, "", "1.2.0.192.in-addr.arpa.", dns.TypePTR); m != nil {
		t.Fatalf("Answer() = %v for an unconfigured reverse zone, want nil", m)
	}
}

func TestTTLApplied(t *testing.T) {
	m := ask(t, "", "kypost.home.arpa.", dns.TypeA)
	if ttl := m.Answer[0].Header().Ttl; ttl != 60 {
		t.Errorf("TTL = %d, want 60", ttl)
	}
}

func TestOwns(t *testing.T) {
	a := authority()
	for name, want := range map[string]bool{
		"kypost.home.arpa.":          true,
		"home.arpa.":                 true,
		"example.com.":               false,
		"20.1.168.192.in-addr.arpa.": true,
		"1.2.0.192.in-addr.arpa.":    false,
		"notarpa":                    false,
	} {
		if got := a.Owns(name); got != want {
			t.Errorf("Owns(%q) = %v, want %v", name, got, want)
		}
	}
}

// A nil snapshot means the first build has not succeeded yet; the handler must
// forward rather than panic.
func TestAnswerNilSnapshot(t *testing.T) {
	m := authority().Answer(nil, "", dns.Question{
		Name: "kypost.home.arpa.", Qtype: dns.TypeA, Qclass: dns.ClassINET,
	})
	if m != nil {
		t.Errorf("Answer() = %v with a nil snapshot, want nil", m)
	}
}

// SetTTL and SetReverseZones must be safe to call while queries are in
// flight: the query path only loads, so a concurrent writer must never make
// -race complain, and no reader may ever observe a half-built value.
func TestAuthoritativeConcurrentSetAndAnswer(t *testing.T) {
	a := authority()
	snap := testSnap(t)
	var wg sync.WaitGroup
	wg.Add(3)
	stop := make(chan struct{})
	go func() {
		defer wg.Done()
		for i := uint32(0); ; i++ {
			select {
			case <-stop:
				return
			default:
				a.SetTTL(i % 100)
			}
		}
	}()
	go func() {
		defer wg.Done()
		zones := []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}
		for {
			select {
			case <-stop:
				return
			default:
				a.SetReverseZones(zones)
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 2000; i++ {
			a.Answer(snap, "", dns.Question{Name: "kypost.home.arpa.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
			a.Owns("20.1.168.192.in-addr.arpa.")
		}
		close(stop)
	}()
	wg.Wait()
}

// A zero-value Authoritative skips NewAuthoritative and so has neither zone
// nor reverse zones stored. Owns must not panic on either nil pointer — a
// deref here takes the whole process down, since the dns package does not
// recover handler panics.
func TestOwnsOnZeroValueAuthoritative(t *testing.T) {
	a := &Authoritative{}
	if got := a.Owns("20.1.168.192.in-addr.arpa."); got {
		t.Errorf("Owns(%q) = true on a zero-value Authoritative, want false", "20.1.168.192.in-addr.arpa.")
	}
	// An empty zone must not make every name ours via the "."-suffix test.
	if got := a.Owns("example.com."); got {
		t.Error("Owns = true with no zone stored, want false")
	}
}

// The private domain is editable at runtime, so a rename has to change what
// the server answers for without a restart.
func TestSetZoneChangesWhatIsOwned(t *testing.T) {
	a := NewAuthoritative("home.arpa.", 60, nil)
	if !a.Owns("nas.home.arpa.") {
		t.Fatal("Owns(nas.home.arpa.) = false before the rename")
	}

	a.SetZone("lan.example")

	if a.Owns("nas.home.arpa.") {
		t.Error("still authoritative for the old zone after SetZone")
	}
	if !a.Owns("nas.lan.example.") {
		t.Error("not authoritative for the new zone after SetZone")
	}
	if got := a.Zone(); got != "lan.example." {
		t.Errorf("Zone() = %q, want the normalized FQDN", got)
	}
	if soa := a.SOA(1); soa.Hdr.Name != "lan.example." || soa.Ns != "ns.lan.example." {
		t.Errorf("SOA still names the old zone: %+v", soa)
	}
}
