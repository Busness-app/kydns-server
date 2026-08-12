package policy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yoshiofthewire/kydns-server/internal/registry"
	"github.com/yoshiofthewire/kydns-server/internal/store"
)

func newService(t *testing.T, srv *httptest.Server) (*store.Store, *Service) {
	t.Helper()
	st, ref, h := newRefresher(t, srv)
	return st, NewService(st, h, ref)
}

func quietServer(t *testing.T, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestPutListRejectsBadDefinitions(t *testing.T) {
	srv := quietServer(t, "ads.example\n")
	_, svc := newService(t, srv)
	cases := map[string]store.BlacklistList{
		"no name":        {URL: "https://e/x", Format: FormatDomains},
		"no url":         {Name: "l", Format: FormatDomains},
		"plain http":     {Name: "l", URL: "http://e/x", Format: FormatDomains},
		"file url":       {Name: "l", URL: "file:///etc/passwd", Format: FormatDomains},
		"unknown format": {Name: "l", URL: "https://e/x", Format: "regex"},
		"tiny interval":  {Name: "l", URL: "https://e/x", Format: FormatDomains, IntervalSeconds: 5},
	}
	for label, l := range cases {
		if _, err := svc.PutList(l); err == nil {
			t.Errorf("PutList(%s) succeeded, want a validation error", label)
		} else {
			var ve *registry.ValidationError
			if !errors.As(err, &ve) {
				t.Errorf("PutList(%s) = %T, want a *registry.ValidationError", label, err)
			}
		}
	}
}

func TestPutListDefaultsTheInterval(t *testing.T) {
	srv := quietServer(t, "ads.example\n")
	st, svc := newService(t, srv)
	id, err := svc.PutList(store.BlacklistList{Name: "l", URL: "https://e/x", Format: FormatDomains, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	got, err := st.BlacklistListByID(id)
	if err != nil {
		t.Fatal(err)
	}
	if got.IntervalSeconds != defaultInterval {
		t.Errorf("IntervalSeconds = %d, want the %d default", got.IntervalSeconds, defaultInterval)
	}
}

// A built-in may be turned off, but never deleted or re-pointed: that is what
// makes it a shipped source rather than a suggestion.
func TestBuiltinListIsProtected(t *testing.T) {
	srv := quietServer(t, "ads.example\n")
	st, svc := newService(t, srv)
	if err := SeedBuiltins(st); err != nil {
		t.Fatal(err)
	}
	lists, err := svc.Lists()
	if err != nil {
		t.Fatal(err)
	}
	b := lists[0]
	if !b.Builtin {
		t.Fatalf("first list = %+v, want the seeded built-in", b)
	}
	if err := svc.DeleteList(b.ID); err == nil {
		t.Error("DeleteList() removed a built-in")
	}
	moved := b
	moved.URL = "https://elsewhere.example/hosts"
	if _, err := svc.PutList(moved); err == nil {
		t.Error("PutList() re-pointed a built-in at another URL")
	}
	off := b
	off.Enabled = false
	if _, err := svc.PutList(off); err != nil {
		t.Errorf("PutList() could not disable a built-in: %v", err)
	}
}

func TestAddRuleNormalizesAndValidates(t *testing.T) {
	srv := quietServer(t, "ads.example\n")
	st, svc := newService(t, srv)
	if _, err := svc.AddRule("deny", "  ADS.Example.  "); err != nil {
		t.Fatal(err)
	}
	rules, err := st.BlacklistRules()
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[0].Domain != "ads.example" {
		t.Errorf("rules = %+v, want the normalized domain", rules)
	}
	if _, err := svc.AddRule("maybe", "x.example"); err == nil {
		t.Error("AddRule() accepted an unknown kind")
	}
	if _, err := svc.AddRule("deny", "not a domain"); err == nil {
		t.Error("AddRule() accepted a malformed domain")
	}
}

func TestConflictingRuleIsRefused(t *testing.T) {
	srv := quietServer(t, "ads.example\n")
	_, svc := newService(t, srv)
	if _, err := svc.AddRule("deny", "ads.example"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AddRule("allow", "ads.example"); !errors.Is(err, store.ErrDuplicateName) {
		t.Errorf("conflicting rule = %v, want ErrDuplicateName", err)
	}
}

func TestSetSettingsBoundsTheBlockTTL(t *testing.T) {
	srv := quietServer(t, "ads.example\n")
	_, svc := newService(t, srv)
	for _, ttl := range []int{0, -1, 3601} {
		if err := svc.SetSettings(true, ttl); err == nil {
			t.Errorf("SetSettings(ttl=%d) succeeded, want a validation error", ttl)
		}
	}
	if err := svc.SetSettings(false, 30); err != nil {
		t.Fatal(err)
	}
	got, err := svc.Settings()
	if err != nil {
		t.Fatal(err)
	}
	if got.Enabled || got.BlockTTL != 30 {
		t.Errorf("Settings() = %+v, want {false 30}", got)
	}
}

// The toggle takes effect without a restart, and re-enabling restores the
// existing snapshots immediately.
func TestTogglingFilteringTakesEffectAtOnce(t *testing.T) {
	srv := quietServer(t, "ads.example\n")
	st, svc := newService(t, srv)
	id, err := svc.PutList(store.BlacklistList{
		Name: "l1", URL: srv.URL, Format: FormatDomains, Enabled: true, IntervalSeconds: 3600,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Refresh(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if d, _ := svc.Test("ads.example"); !d.Blocked {
		t.Fatal("the name is not blocked after a refresh")
	}
	if err := svc.SetSettings(false, 60); err != nil {
		t.Fatal(err)
	}
	if d, _ := svc.Test("ads.example"); d.Blocked {
		t.Error("the name is still blocked with filtering off")
	}
	if err := svc.SetSettings(true, 60); err != nil {
		t.Fatal(err)
	}
	if d, _ := svc.Test("ads.example"); !d.Blocked {
		t.Error("re-enabling did not restore the snapshot")
	}
	// The list body was never deleted by the toggle.
	got, err := st.BlacklistListByID(id)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Snapshot) != 1 {
		t.Errorf("Snapshot = %v, want the body untouched by the toggle", got.Snapshot)
	}
}

func TestTestReportsTheDecidingList(t *testing.T) {
	srv := quietServer(t, "ads.example\n")
	_, svc := newService(t, srv)
	id, err := svc.PutList(store.BlacklistList{
		Name: "l1", URL: srv.URL, Format: FormatDomains, Enabled: true, IntervalSeconds: 3600,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Refresh(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	d, err := svc.Test("cdn.ads.example")
	if err != nil {
		t.Fatal(err)
	}
	if !d.Blocked || d.Policy != "l1" {
		t.Errorf("Test(cdn.ads.example) = %+v, want blocked by l1", d)
	}
	if d, err := svc.Test("example.org"); err != nil || d.Blocked || d.Policy != PolicyForwarded {
		t.Errorf("Test(example.org) = %+v %v, want forwarded", d, err)
	}
	if _, err := svc.Test("not a domain"); err == nil {
		t.Error("Test() accepted a malformed name")
	}
}

// Deleting a list must stop its blocks at once, not at the next refresh.
func TestDeletingAListStopsItsBlocks(t *testing.T) {
	srv := quietServer(t, "ads.example\n")
	_, svc := newService(t, srv)
	id, err := svc.PutList(store.BlacklistList{
		Name: "l1", URL: srv.URL, Format: FormatDomains, Enabled: true, IntervalSeconds: 3600,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Refresh(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if err := svc.DeleteList(id); err != nil {
		t.Fatal(err)
	}
	if d, _ := svc.Test("ads.example"); d.Blocked {
		t.Errorf("Test() = %+v after the list was deleted, want forwarded", d)
	}
}
