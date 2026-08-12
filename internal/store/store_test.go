package store

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "kydns.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestMigrationsAreIdempotent(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "kydns.db")
	for i := 0; i < 2; i++ {
		s, err := Open(p)
		if err != nil {
			t.Fatalf("Open() attempt %d: %v", i, err)
		}
		s.Close()
	}
}

func TestViewRoundTrip(t *testing.T) {
	s := open(t)
	if err := s.PutView(View{Name: "tailnet", Subnets: []string{"100.64.0.0/10"}}); err != nil {
		t.Fatal(err)
	}
	views, err := s.Views()
	if err != nil {
		t.Fatal(err)
	}
	if len(views) != 1 || views[0].Name != "tailnet" {
		t.Fatalf("Views() = %+v, want one tailnet view", views)
	}
	if len(views[0].Subnets) != 1 || views[0].Subnets[0] != "100.64.0.0/10" {
		t.Errorf("Subnets = %v", views[0].Subnets)
	}
}

func TestDuplicateCIDRAcrossViewsRejected(t *testing.T) {
	s := open(t)
	if err := s.PutView(View{Name: "a", Subnets: []string{"10.0.0.0/8"}}); err != nil {
		t.Fatal(err)
	}
	err := s.PutView(View{Name: "b", Subnets: []string{"10.0.0.0/8"}})
	if !errors.Is(err, ErrDuplicateCIDR) {
		t.Fatalf("PutView() error = %v, want ErrDuplicateCIDR", err)
	}
}

func TestDeleteViewInUseRejected(t *testing.T) {
	s := open(t)
	if err := s.PutView(View{Name: "tailnet", Subnets: []string{"100.64.0.0/10"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PutService(Service{
		Name:      "kypost",
		Addresses: []Address{{Address: "100.101.102.103", View: "tailnet"}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteView("tailnet"); !errors.Is(err, ErrViewInUse) {
		t.Fatalf("DeleteView() error = %v, want ErrViewInUse", err)
	}
}

func TestServiceRoundTripWithMixedViewTags(t *testing.T) {
	s := open(t)
	if err := s.PutView(View{Name: "tailnet", Subnets: []string{"100.64.0.0/10"}}); err != nil {
		t.Fatal(err)
	}
	id, err := s.PutService(Service{
		Name: "kypost",
		Addresses: []Address{
			{Address: "192.168.1.20"},
			{Address: "100.101.102.103", View: "tailnet"},
		},
		Aliases: []string{"webmail"},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Service(id)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Addresses) != 2 {
		t.Fatalf("Addresses = %+v, want 2", got.Addresses)
	}
	var untagged, tagged int
	for _, a := range got.Addresses {
		if a.View == "" {
			untagged++
		} else if a.View == "tailnet" {
			tagged++
		}
	}
	if untagged != 1 || tagged != 1 {
		t.Errorf("untagged=%d tagged=%d, want 1 and 1", untagged, tagged)
	}
	if len(got.Aliases) != 1 || got.Aliases[0] != "webmail" {
		t.Errorf("Aliases = %v", got.Aliases)
	}
}

func TestServiceNotFound(t *testing.T) {
	s := open(t)
	if _, err := s.Service(404); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Service() error = %v, want ErrNotFound", err)
	}
}

func TestDuplicateServiceNameRejected(t *testing.T) {
	s := open(t)
	svc := Service{Name: "kypost", Addresses: []Address{{Address: "192.168.1.20"}}}
	if _, err := s.PutService(svc); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PutService(svc); !errors.Is(err, ErrDuplicateName) {
		t.Fatalf("PutService() error = %v, want ErrDuplicateName", err)
	}
}

// Updating an existing service replaces its addresses and aliases rather than
// appending, so an edit cannot silently accumulate stale rows.
func TestPutServiceReplacesChildren(t *testing.T) {
	s := open(t)
	id, err := s.PutService(Service{
		Name:      "kypost",
		Addresses: []Address{{Address: "192.168.1.20"}},
		Aliases:   []string{"webmail", "mail"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.PutService(Service{
		ID:        id,
		Name:      "kypost",
		Addresses: []Address{{Address: "192.168.1.21"}},
		Aliases:   []string{"webmail"},
	}); err != nil {
		t.Fatal(err)
	}
	got, err := s.Service(id)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Addresses) != 1 || got.Addresses[0].Address != "192.168.1.21" {
		t.Errorf("Addresses = %+v, want only the replacement", got.Addresses)
	}
	if len(got.Aliases) != 1 {
		t.Errorf("Aliases = %v, want only the replacement", got.Aliases)
	}
}

func TestRecordRoundTripAndDelete(t *testing.T) {
	s := open(t)
	id, err := s.PutRecord(Record{Name: "printer.home.arpa.", Type: "A", Value: "192.168.1.50"})
	if err != nil {
		t.Fatal(err)
	}
	recs, err := s.Records()
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].Name != "printer.home.arpa." {
		t.Fatalf("Records() = %+v", recs)
	}
	if err := s.DeleteRecord(id); err != nil {
		t.Fatal(err)
	}
	if recs, _ = s.Records(); len(recs) != 0 {
		t.Errorf("Records() = %+v after delete, want empty", recs)
	}
	if err := s.DeleteRecord(id); !errors.Is(err, ErrNotFound) {
		t.Errorf("second DeleteRecord() error = %v, want ErrNotFound", err)
	}
}

// Deleting a service must take its addresses and aliases with it, so an alias
// name is free for reuse afterwards.
func TestDeleteServiceCascades(t *testing.T) {
	s := open(t)
	id, err := s.PutService(Service{
		Name:      "kypost",
		Addresses: []Address{{Address: "192.168.1.20"}},
		Aliases:   []string{"webmail"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteService(id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PutService(Service{
		Name:      "other",
		Addresses: []Address{{Address: "192.168.1.21"}},
		Aliases:   []string{"webmail"},
	}); err != nil {
		t.Errorf("alias not released by cascade: %v", err)
	}
}

// A database created before proxy routing existed must gain the new columns
// on open, not fail. This is the first schema change since v1 shipped with
// live data in it.
func TestOpenMigratesAnOlderDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")

	// Build a v1-shaped services table by hand, with a row in it.
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE services (
		id             INTEGER PRIMARY KEY,
		name           TEXT NOT NULL UNIQUE,
		check_url      TEXT NOT NULL DEFAULT '',
		check_insecure INTEGER NOT NULL DEFAULT 0,
		created_at     INTEGER NOT NULL DEFAULT (unixepoch())
	)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO services(name) VALUES('legacy')`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open() on a pre-migration database: %v", err)
	}

	svcs, err := s.Services()
	if err != nil {
		t.Fatal(err)
	}
	if len(svcs) != 1 || svcs[0].Name != "legacy" {
		t.Fatalf("Services() = %v, want the pre-existing row preserved", svcs)
	}
	if svcs[0].ProxyAddress != "" || svcs[0].RouteViaProxy {
		t.Errorf("migrated row = %+v, want the new fields at their zero values", svcs[0])
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopening an already-migrated database is the path a live deployment
	// takes on every restart after the upgrade; it must not try to reapply
	// the ALTERs or lose the row.
	s, err = Open(path)
	if err != nil {
		t.Fatalf("reopen of a migrated database: %v", err)
	}
	defer s.Close()
	svcs, err = s.Services()
	if err != nil {
		t.Fatal(err)
	}
	if len(svcs) != 1 || svcs[0].Name != "legacy" {
		t.Fatalf("Services() after reopen = %v, want the row still there", svcs)
	}
	if svcs[0].ProxyAddress != "" || svcs[0].RouteViaProxy {
		t.Errorf("reopened row = %+v, want the new fields at their zero values", svcs[0])
	}
}

func TestServiceRoundTripsProxyFields(t *testing.T) {
	s := open(t)
	id, err := s.PutService(Service{
		Name:          "kypost",
		Addresses:     []Address{{Address: "192.168.1.30"}},
		ProxyAddress:  "192.168.1.20",
		RouteViaProxy: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Service(id)
	if err != nil {
		t.Fatal(err)
	}
	if got.ProxyAddress != "192.168.1.20" || !got.RouteViaProxy {
		t.Errorf("Service() = %+v, want the proxy fields preserved", got)
	}

	// Turning routing off keeps the address, which is the point of two fields.
	got.RouteViaProxy = false
	if _, err := s.PutService(got); err != nil {
		t.Fatal(err)
	}
	got, err = s.Service(id)
	if err != nil {
		t.Fatal(err)
	}
	if got.ProxyAddress != "192.168.1.20" || got.RouteViaProxy {
		t.Errorf("Service() = %+v, want the address kept and routing off", got)
	}
}

// ReplaceAll must be all-or-nothing: a document that fails partway through
// must leave the prior registry untouched, not half-wiped.
func TestReplaceAllRollsBackOnFailure(t *testing.T) {
	s := open(t)
	if _, err := s.PutService(Service{
		Name:      "keeper",
		Addresses: []Address{{Address: "192.168.1.9"}},
	}); err != nil {
		t.Fatal(err)
	}

	err := s.ReplaceAll(nil, []Service{
		{Name: "dup", Addresses: []Address{{Address: "192.168.1.10"}}},
		{Name: "dup", Addresses: []Address{{Address: "192.168.1.11"}}},
	}, nil)
	if !errors.Is(err, ErrDuplicateName) {
		t.Fatalf("ReplaceAll() error = %v, want ErrDuplicateName", err)
	}

	svcs, err := s.Services()
	if err != nil {
		t.Fatal(err)
	}
	if len(svcs) != 1 || svcs[0].Name != "keeper" {
		t.Fatalf("Services() after a failed replace = %+v, want only keeper untouched", svcs)
	}
}
