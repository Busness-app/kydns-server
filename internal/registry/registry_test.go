package registry

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yoshiofthewire/kydns-server/internal/store"
)

func newRegistry(t *testing.T) (*Registry, *int) {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "kydns.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	rebuilds := 0
	r := New(s, "home.arpa.", func() error { rebuilds++; return nil })
	return r, &rebuilds
}

func TestPutServiceNormalizesAndRebuilds(t *testing.T) {
	r, rebuilds := newRegistry(t)
	id, err := r.PutService(store.Service{
		Name:      "KyPost",
		Addresses: []store.Address{{Address: "192.168.1.20"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if id == 0 {
		t.Fatal("PutService() returned id 0")
	}
	if *rebuilds != 1 {
		t.Errorf("rebuilds = %d, want 1", *rebuilds)
	}
	svcs, err := r.Services()
	if err != nil {
		t.Fatal(err)
	}
	if svcs[0].Name != "kypost" {
		t.Errorf("Name = %q, want lowercased kypost", svcs[0].Name)
	}
}

func TestPutServiceRejectsBadInput(t *testing.T) {
	r, _ := newRegistry(t)
	cases := map[string]store.Service{
		"empty name":     {Addresses: []store.Address{{Address: "192.168.1.20"}}},
		"bad label":      {Name: "has_underscore", Addresses: []store.Address{{Address: "192.168.1.20"}}},
		"bad address":    {Name: "ok", Addresses: []store.Address{{Address: "nope"}}},
		"no address":     {Name: "ok"},
		"unknown view":   {Name: "ok", Addresses: []store.Address{{Address: "192.168.1.20", View: "ghost"}}},
		"wildcard":       {Name: "*", Addresses: []store.Address{{Address: "192.168.1.20"}}},
		"alias conflict": {Name: "ok", Addresses: []store.Address{{Address: "192.168.1.20"}}, Aliases: []string{"bad_alias"}},
	}
	for name, svc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := r.PutService(svc); err == nil {
				t.Fatal("PutService() error = nil, want validation error")
			}
		})
	}
}

// A rejected write must not leave a rebuild behind.
func TestFailedWriteDoesNotRebuild(t *testing.T) {
	r, rebuilds := newRegistry(t)
	if _, err := r.PutService(store.Service{Name: "bad_name"}); err == nil {
		t.Fatal("want validation error")
	}
	if *rebuilds != 0 {
		t.Errorf("rebuilds = %d after a failed write, want 0", *rebuilds)
	}
}

func TestPutViewValidatesCIDRs(t *testing.T) {
	r, _ := newRegistry(t)
	if err := r.PutView(store.View{Name: "tailnet", Subnets: []string{"100.64.0.0/10"}}); err != nil {
		t.Fatal(err)
	}
	if err := r.PutView(store.View{Name: "bad", Subnets: []string{"not-a-cidr"}}); err == nil {
		t.Error("PutView() accepted an invalid CIDR")
	}
	if err := r.PutView(store.View{Name: "", Subnets: []string{"10.0.0.0/8"}}); err == nil {
		t.Error("PutView() accepted an empty name")
	}
	if err := r.PutView(store.View{Name: "nosubnets"}); err == nil {
		t.Error("PutView() accepted a view with no subnets")
	}
}

// An unmasked CIDR is stored masked, so the matcher and the UI agree.
func TestPutViewMasksCIDRs(t *testing.T) {
	r, _ := newRegistry(t)
	if err := r.PutView(store.View{Name: "lan", Subnets: []string{"192.168.1.5/24"}}); err != nil {
		t.Fatal(err)
	}
	views, err := r.Views()
	if err != nil {
		t.Fatal(err)
	}
	if views[0].Subnets[0] != "192.168.1.0/24" {
		t.Errorf("stored subnet = %q, want the masked form", views[0].Subnets[0])
	}
}

func TestDeleteViewInUse(t *testing.T) {
	r, _ := newRegistry(t)
	if err := r.PutView(store.View{Name: "tailnet", Subnets: []string{"100.64.0.0/10"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.PutService(store.Service{
		Name:      "kypost",
		Addresses: []store.Address{{Address: "100.101.102.103", View: "tailnet"}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := r.DeleteView("tailnet"); !errors.Is(err, store.ErrViewInUse) {
		t.Errorf("DeleteView() error = %v, want ErrViewInUse", err)
	}
}

func TestPutRecordValidates(t *testing.T) {
	r, _ := newRegistry(t)
	if _, err := r.PutRecord(store.Record{Name: "printer.home.arpa.", Type: "A", Value: "192.168.1.50"}); err != nil {
		t.Fatal(err)
	}
	for name, rec := range map[string]store.Record{
		"unsupported type": {Name: "x.home.arpa.", Type: "TXT", Value: "hi"},
		"out of zone":      {Name: "x.example.com.", Type: "A", Value: "192.168.1.1"},
		"bad address":      {Name: "x.home.arpa.", Type: "A", Value: "nope"},
		"ptr not arpa":     {Name: "x.home.arpa.", Type: "PTR", Value: "y.home.arpa."},
		"unknown view":     {Name: "x.home.arpa.", Type: "A", Value: "192.168.1.1", View: "ghost"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := r.PutRecord(rec); err == nil {
				t.Fatal("PutRecord() error = nil, want validation error")
			}
		})
	}
}

func TestPutRecordAcceptsPTRInArpa(t *testing.T) {
	r, _ := newRegistry(t)
	if _, err := r.PutRecord(store.Record{
		Name: "50.1.168.192.in-addr.arpa.", Type: "PTR", Value: "printer.home.arpa.",
	}); err != nil {
		t.Fatalf("PutRecord() = %v, want a PTR in .arpa to be accepted", err)
	}
}

func TestTokenLifecycle(t *testing.T) {
	r, _ := newRegistry(t)
	plaintext, err := r.CreateToken("laptop")
	if err != nil {
		t.Fatal(err)
	}
	if len(plaintext) < 20 {
		t.Errorf("token %q is too short", plaintext)
	}
	if !r.AuthenticateToken(plaintext) {
		t.Error("AuthenticateToken() rejected a freshly created token")
	}
	if r.AuthenticateToken("kydns_wrong") {
		t.Error("AuthenticateToken() accepted a bogus token")
	}
	if r.AuthenticateToken("no-prefix") {
		t.Error("AuthenticateToken() accepted a token without the prefix")
	}
	toks, err := r.Tokens()
	if err != nil {
		t.Fatal(err)
	}
	if len(toks) != 1 {
		t.Fatalf("Tokens() = %d entries, want 1", len(toks))
	}
	// The plaintext must never be recoverable from storage.
	if toks[0].Hash == plaintext {
		t.Error("token stored in plaintext")
	}
	if err := r.DeleteToken(toks[0].ID); err != nil {
		t.Fatal(err)
	}
	if r.AuthenticateToken(plaintext) {
		t.Error("a revoked token still authenticates")
	}
}

// Two tokens must both work; authentication scans every stored hash.
func TestMultipleTokens(t *testing.T) {
	r, _ := newRegistry(t)
	a, err := r.CreateToken("a")
	if err != nil {
		t.Fatal(err)
	}
	b, err := r.CreateToken("b")
	if err != nil {
		t.Fatal(err)
	}
	if !r.AuthenticateToken(a) || !r.AuthenticateToken(b) {
		t.Error("not every token authenticates")
	}
}

func TestPutServiceValidatesProxy(t *testing.T) {
	r, _ := newRegistry(t)

	// Routing on with nowhere to route is the one invalid combination the
	// two-field design makes possible.
	_, err := r.PutService(store.Service{
		Name:          "kypost",
		Addresses:     []store.Address{{Address: "192.168.1.30"}},
		RouteViaProxy: true,
	})
	if err == nil {
		t.Fatal("PutService() error = nil with routing on and no proxy address")
	}
	if !strings.Contains(err.Error(), "proxy") {
		t.Errorf("error = %v, want it to name the proxy address", err)
	}

	if _, err := r.PutService(store.Service{
		Name:          "nas",
		Addresses:     []store.Address{{Address: "192.168.1.30"}},
		ProxyAddress:  "not-an-ip",
		RouteViaProxy: true,
	}); err == nil {
		t.Error("PutService() error = nil with a malformed proxy address")
	}

	// An address kept while routing is off is deliberate, not an error.
	if _, err := r.PutService(store.Service{
		Name:         "git",
		Addresses:    []store.Address{{Address: "192.168.1.30"}},
		ProxyAddress: "192.168.1.20",
	}); err != nil {
		t.Errorf("PutService() with routing off rejected: %v", err)
	}
}
