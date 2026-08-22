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

// The rebuild after a replace is what stops DNS serving stale data; a
// successful import must trigger it exactly once.
func TestReplaceAllRebuildsOnce(t *testing.T) {
	r, rebuilds := newRegistry(t)
	if _, err := r.PutService(store.Service{
		Name: "keeper", Addresses: []store.Address{{Address: "192.168.1.9"}},
	}); err != nil {
		t.Fatal(err)
	}
	*rebuilds = 0

	if err := r.ReplaceAll(nil, []store.Service{
		{Name: "fresh", Addresses: []store.Address{{Address: "192.168.1.10"}}},
	}, nil); err != nil {
		t.Fatal(err)
	}
	if *rebuilds != 1 {
		t.Errorf("rebuilds = %d, want 1", *rebuilds)
	}
}

// A rejected replace must not rebuild, or a bad import would still flip DNS
// over to a half-applied snapshot.
func TestReplaceAllValidationFailureDoesNotRebuild(t *testing.T) {
	r, rebuilds := newRegistry(t)
	err := r.ReplaceAll(nil, []store.Service{
		{Name: "bad_name", Addresses: []store.Address{{Address: "192.168.1.30"}}},
	}, nil)
	if err == nil {
		t.Fatal("ReplaceAll() error = nil, want validation error")
	}
	if *rebuilds != 0 {
		t.Errorf("rebuilds = %d after a rejected replace, want 0", *rebuilds)
	}
}

// ReplaceAll must normalize the same way PutService/PutRecord/PutView do, or
// a hand-edited YAML with mixed case or stray whitespace would store names
// that don't match how DNS queries and the zone build normalize theirs.
func TestReplaceAllNormalizes(t *testing.T) {
	r, _ := newRegistry(t)
	if err := r.ReplaceAll(
		[]store.View{{Name: "Tailnet", Subnets: []string{"100.64.0.0/10"}}},
		[]store.Service{{
			Name:         "KyPost",
			Addresses:    []store.Address{{Address: "192.168.1.30"}},
			ProxyAddress: " 192.168.1.20 ",
		}},
		[]store.Record{{Name: "Printer.Home.Arpa.", Type: "a", Value: "192.168.1.50"}},
	); err != nil {
		t.Fatal(err)
	}

	views, err := r.Views()
	if err != nil {
		t.Fatal(err)
	}
	if views[0].Name != "tailnet" {
		t.Errorf("view name = %q, want lowercased tailnet", views[0].Name)
	}

	svcs, err := r.Services()
	if err != nil {
		t.Fatal(err)
	}
	if svcs[0].Name != "kypost" || svcs[0].ProxyAddress != "192.168.1.20" {
		t.Errorf("service = %+v, want the lowercased name and trimmed proxy address", svcs[0])
	}

	recs, err := r.Records()
	if err != nil {
		t.Fatal(err)
	}
	if recs[0].Name != "printer.home.arpa." || recs[0].Type != "A" {
		t.Errorf("record = %+v, want the normalized name and uppercased type", recs[0])
	}
}

func TestPutServiceNormalizesMAC(t *testing.T) {
	r, _ := newRegistry(t)
	id, err := r.PutService(store.Service{
		Name:      "kypost",
		Addresses: []store.Address{{Address: "192.168.1.20"}},
		MAC:       "AA-BB-CC-DD-EE-FF",
	})
	if err != nil {
		t.Fatalf("PutService: %v", err)
	}
	got, err := r.Service(id)
	if err != nil {
		t.Fatalf("Service: %v", err)
	}
	if got.MAC != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("stored MAC = %q, want the normalized form", got.MAC)
	}
}

func TestPutServiceRejectsAMalformedMAC(t *testing.T) {
	r, _ := newRegistry(t)
	_, err := r.PutService(store.Service{
		Name: "kypost", Addresses: []store.Address{{Address: "192.168.1.20"}},
		MAC: "nonsense",
	})
	var ve *ValidationError
	if !errors.As(err, &ve) || ve.Field != "mac" {
		t.Fatalf("PutService with a malformed MAC = %v, want a validation error on mac", err)
	}
}

func TestPutServiceRejectsADuplicateMAC(t *testing.T) {
	r, _ := newRegistry(t)
	if _, err := r.PutService(store.Service{
		Name: "one", Addresses: []store.Address{{Address: "192.168.1.20"}},
		MAC: "aa:bb:cc:dd:ee:ff",
	}); err != nil {
		t.Fatalf("first PutService: %v", err)
	}
	_, err := r.PutService(store.Service{
		Name: "two", Addresses: []store.Address{{Address: "192.168.1.21"}},
		MAC: "AA:BB:CC:DD:EE:FF", // same MAC, different spelling
	})
	var ve *ValidationError
	if !errors.As(err, &ve) || ve.Field != "mac" || ve.Code != "duplicate" {
		t.Fatalf("PutService accepted two services reserving one MAC: err = %v", err)
	}
}

func TestPutServiceAllowsManyServicesWithNoMAC(t *testing.T) {
	r, _ := newRegistry(t)
	for _, n := range []string{"one", "two", "three"} {
		if _, err := r.PutService(store.Service{
			Name: n, Addresses: []store.Address{{Address: "192.168.1.20"}},
		}); err != nil {
			t.Fatalf("PutService(%s): %v", n, err)
		}
	}
}

func TestPutServiceKeepsItsOwnMACOnUpdate(t *testing.T) {
	r, _ := newRegistry(t)
	id, err := r.PutService(store.Service{
		Name: "one", Addresses: []store.Address{{Address: "192.168.1.20"}},
		MAC: "aa:bb:cc:dd:ee:ff",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// Re-saving the same service must not trip the duplicate check against
	// itself.
	if _, err := r.PutService(store.Service{
		ID: id, Name: "one", Addresses: []store.Address{{Address: "192.168.1.99"}},
		MAC: "aa:bb:cc:dd:ee:ff",
	}); err != nil {
		t.Fatalf("update: %v", err)
	}
}

// macUnique's own empty-MAC guard, not PutService's, is what lets an import
// document contain any number of unreserved services.
func TestReplaceAllAllowsManyServicesWithNoMAC(t *testing.T) {
	r, _ := newRegistry(t)
	if err := r.ReplaceAll(nil, []store.Service{
		{Name: "one", Addresses: []store.Address{{Address: "192.168.1.20"}}},
		{Name: "two", Addresses: []store.Address{{Address: "192.168.1.20"}}},
		{Name: "three", Addresses: []store.Address{{Address: "192.168.1.20"}}},
	}, nil); err != nil {
		t.Fatalf("ReplaceAll: %v", err)
	}
	got, err := r.Services()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d services, want 3", len(got))
	}
}

// ReplaceAll validates the whole document before writing any of it, so its
// duplicate check has to look at the document rather than at the store it is
// about to wipe. Every imported service arrives with ID 0, which is exactly
// the case an "is this me?" check by ID gets wrong.
func TestReplaceAllRejectsADuplicateMACInTheDocument(t *testing.T) {
	r, _ := newRegistry(t)
	err := r.ReplaceAll(nil, []store.Service{
		{Name: "one", Addresses: []store.Address{{Address: "192.168.1.20"}}, MAC: "aa:bb:cc:dd:ee:ff"},
		{Name: "two", Addresses: []store.Address{{Address: "192.168.1.21"}}, MAC: "AA-BB-CC-DD-EE-FF"},
	}, nil)
	var ve *ValidationError
	if !errors.As(err, &ve) || ve.Field != "mac" || ve.Code != "duplicate" {
		t.Fatalf("ReplaceAll accepted a document reserving one MAC twice: err = %v", err)
	}
}

// A replacement document is validated against itself, not against the
// services it is replacing, so re-importing an export must not collide with
// the rows it is about to delete.
func TestReplaceAllAcceptsAMACAlreadyInTheStore(t *testing.T) {
	r, _ := newRegistry(t)
	if _, err := r.PutService(store.Service{
		Name: "one", Addresses: []store.Address{{Address: "192.168.1.20"}},
		MAC: "aa:bb:cc:dd:ee:ff",
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := r.ReplaceAll(nil, []store.Service{
		{Name: "one", Addresses: []store.Address{{Address: "192.168.1.20"}}, MAC: "aa:bb:cc:dd:ee:ff"},
	}, nil); err != nil {
		t.Fatalf("ReplaceAll re-importing the same reservation: %v", err)
	}
}
