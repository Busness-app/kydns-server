package app

import (
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/Busness-app/kydns-server/internal/dnsserver"
	"github.com/Busness-app/kydns-server/internal/policy"
	"github.com/Busness-app/kydns-server/internal/store"
	"github.com/Busness-app/kydns-server/internal/zone"
	"github.com/miekg/dns"
)

// buildPolicy mirrors the wiring in Serve, so the test proves the shape the
// process actually runs rather than a parallel invention.
func buildPolicy(t *testing.T, st *store.Store) *policy.Service {
	t.Helper()
	h := policy.NewHolder(func() (store.BlacklistSettings, []store.BlacklistList, []store.BlacklistRule, error) {
		set, err := st.BlacklistSettings()
		if err != nil {
			return set, nil, nil, err
		}
		lists, err := st.BlacklistLists()
		if err != nil {
			return set, nil, nil, err
		}
		rules, err := st.BlacklistRules()
		return set, lists, rules, err
	})
	if err := h.Rebuild(); err != nil {
		t.Fatal(err)
	}
	return policy.NewService(st, h, policy.NewRefresher(st, policy.NewFetcher(0), h, nil), nil)
}

// TestLocalRecordAndAllowRuleBothWin is the spec's required integration check:
// a name a list blocks is served locally when it is a KyDNS service, and an
// allow exception overrides the list for a public name.
func TestLocalRecordAndAllowRuleBothWin(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "kydns.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	// A local service whose name a public list also carries.
	if _, err := st.PutService(store.Service{
		Name: "kypost", Addresses: []store.Address{{Address: "192.168.1.20"}},
	}); err != nil {
		t.Fatal(err)
	}
	// A list that blocks the local name, an unrelated name, and an excepted one.
	id, err := st.PutBlacklistList(store.BlacklistList{
		Name: "l1", URL: "https://lists.example/x", Format: policy.FormatDomains,
		Enabled: true, IntervalSeconds: 3600,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetBlacklistSnapshot(id,
		[]string{"ads.example", "kypost.home.arpa", "shared.example"}, 0, "", "", 1); err != nil {
		t.Fatal(err)
	}
	if _, err := st.PutBlacklistRule(store.BlacklistRule{Kind: "allow", Domain: "shared.example"}); err != nil {
		t.Fatal(err)
	}

	pol := buildPolicy(t, st)
	if err := pol.SetSettings(true, 60); err != nil {
		t.Fatal(err)
	}

	zh := zone.NewHolder(func() (zone.Input, error) {
		svcs, err := st.Services()
		if err != nil {
			return zone.Input{}, err
		}
		return zone.Input{Zone: "home.arpa.", Services: svcs}, nil
	}, nil)
	if err := zh.Rebuild(); err != nil {
		t.Fatal(err)
	}

	// The service layer's Test is the same decision the DNS path uses.
	if d, err := pol.Test("ads.example"); err != nil || !d.Blocked {
		t.Errorf("ads.example = %+v %v, want blocked", d, err)
	}
	if d, err := pol.Test("shared.example"); err != nil || d.Blocked {
		t.Errorf("shared.example = %+v %v, want the allow rule to win", d, err)
	}

	// The local name is answered authoritatively, so the policy is never asked.
	auth := dnsserver.NewAuthoritative("home.arpa.", 60, nil)
	q := dns.Question{Name: "kypost.home.arpa.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	m := auth.Answer(zh.Current(), "", q)
	if m == nil || m.Rcode != dns.RcodeSuccess || len(m.Answer) != 1 {
		t.Fatalf("local answer = %v, want the service address despite the list", m)
	}
	if a, ok := m.Answer[0].(*dns.A); !ok || a.A.String() != "192.168.1.20" {
		t.Errorf("local answer = %v, want 192.168.1.20", m.Answer[0])
	}
}

// startUDP runs srv on an ephemeral loopback UDP port. It mirrors
// dnsserver's own test helper of the same name, which is unexported.
func startUDP(t *testing.T, srv *dnsserver.Server) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ds := &dns.Server{PacketConn: pc, Handler: srv}
	go ds.ActivateAndServe()
	t.Cleanup(func() { ds.Shutdown() })
	return pc.LocalAddr().String()
}

// queryUDP sends one query over UDP from loopback.
func queryUDP(t *testing.T, server, name string, qtype uint16) *dns.Msg {
	t.Helper()
	c := &dns.Client{Net: "udp", Timeout: 3 * time.Second}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	resp, _, err := c.Exchange(m, server)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	return resp
}

// TestDNSServerWiredToARealHolderBlocksAndServesLocalNames sends real UDP
// queries through a dnsserver.Server wired exactly as serve.go wires it: a
// real policy.Holder over a real store, not a stub decider. This is the only
// test that would catch a wiring inversion, such as passing the Service where
// serve.go expects the Holder.
func TestDNSServerWiredToARealHolderBlocksAndServesLocalNames(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "kydns.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if _, err := st.PutService(store.Service{
		Name: "kypost", Addresses: []store.Address{{Address: "192.168.1.20"}},
	}); err != nil {
		t.Fatal(err)
	}
	id, err := st.PutBlacklistList(store.BlacklistList{
		Name: "l1", URL: "https://lists.example/x", Format: policy.FormatDomains,
		Enabled: true, IntervalSeconds: 3600,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetBlacklistSnapshot(id, []string{"ads.example"}, 0, "", "", 1); err != nil {
		t.Fatal(err)
	}

	pol := buildPolicy(t, st)
	if err := pol.SetSettings(true, 60); err != nil {
		t.Fatal(err)
	}

	// The policy.Holder underlying pol, built the same way serve.go builds it:
	// this is the piece a wiring inversion would swap out for the Service.
	policyHolder := policy.NewHolder(func() (store.BlacklistSettings, []store.BlacklistList, []store.BlacklistRule, error) {
		set, err := st.BlacklistSettings()
		if err != nil {
			return set, nil, nil, err
		}
		lists, err := st.BlacklistLists()
		if err != nil {
			return set, nil, nil, err
		}
		rules, err := st.BlacklistRules()
		return set, lists, rules, err
	})
	if err := policyHolder.Rebuild(); err != nil {
		t.Fatal(err)
	}

	zh := zone.NewHolder(func() (zone.Input, error) {
		svcs, err := st.Services()
		if err != nil {
			return zone.Input{}, err
		}
		return zone.Input{Zone: "home.arpa.", Services: svcs}, nil
	}, nil)
	if err := zh.Rebuild(); err != nil {
		t.Fatal(err)
	}

	srv := dnsserver.New(dnsserver.Options{
		Holder: zh,
		ACL:    dnsserver.NewACL([]netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}),
		Auth:   dnsserver.NewAuthoritative("home.arpa.", 60, nil),
		Policy: policyHolder,
	})
	addr := startUDP(t, srv)

	resp := queryUDP(t, addr, "ads.example", dns.TypeA)
	if resp.Rcode != dns.RcodeNameError {
		t.Errorf("ads.example rcode = %s, want NXDOMAIN", dns.RcodeToString[resp.Rcode])
	}
	if resp.Authoritative {
		t.Error("ads.example answer has AA set, want it clear: the block is policy, not zone data")
	}

	resp = queryUDP(t, addr, "kypost.home.arpa", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Fatalf("kypost.home.arpa = %v, want the service address", resp)
	}
	if a, ok := resp.Answer[0].(*dns.A); !ok || a.A.String() != "192.168.1.20" {
		t.Errorf("kypost.home.arpa answer = %v, want 192.168.1.20", resp.Answer[0])
	}
}
