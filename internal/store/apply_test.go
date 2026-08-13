package store

import "testing"

func baseSettings() Settings {
	return Settings{PrivateDomain: "home.arpa", TTL: 60, CacheMinTTL: 5,
		CacheMaxTTL: 3600, NegativeMaxTTL: 300, CacheEntries: 10000,
		HealthInterval: 30, HealthTimeout: 5, HealthWorkers: 8}
}

func TestApplySnapshotReplacesRegistry(t *testing.T) {
	s := open(t)
	if _, err := s.PutService(Service{Name: "old"}); err != nil {
		t.Fatal(err)
	}
	err := s.ApplySnapshot(SnapshotInput{
		Services: []Service{{Name: "new"}},
		Settings: baseSettings(),
	})
	if err != nil {
		t.Fatal(err)
	}
	svcs, err := s.Services()
	if err != nil {
		t.Fatal(err)
	}
	if len(svcs) != 1 || svcs[0].Name != "new" {
		t.Fatalf("Services() = %+v, want exactly [new]", svcs)
	}
}

// The spec's central failure promise: a bad snapshot degrades a replica to
// stale, never to broken.
func TestApplySnapshotRollsBackEverythingOnFailure(t *testing.T) {
	s := open(t)
	if _, err := s.PutService(Service{Name: "keeper"}); err != nil {
		t.Fatal(err)
	}
	before := baseSettings()
	before.TTL = 60
	if err := s.PutSettings(before); err != nil {
		t.Fatal(err)
	}

	bad := baseSettings()
	bad.TTL = 999
	// Two rules for one domain violate the UNIQUE index, and the violation is
	// reached only after the services and settings writes above it.
	err := s.ApplySnapshot(SnapshotInput{
		Services: []Service{{Name: "replacement"}},
		Settings: bad,
		Rules: []BlacklistRule{
			{Kind: "deny", Domain: "ads.example"},
			{Kind: "allow", Domain: "ads.example"},
		},
	})
	if err == nil {
		t.Fatal("ApplySnapshot() accepted two rules for one domain")
	}

	svcs, err := s.Services()
	if err != nil {
		t.Fatal(err)
	}
	if len(svcs) != 1 || svcs[0].Name != "keeper" {
		t.Fatalf("Services() = %+v after a failed apply, want the untouched [keeper]", svcs)
	}
	got, _, err := s.Settings()
	if err != nil {
		t.Fatal(err)
	}
	if got.TTL != 60 {
		t.Fatalf("TTL = %d after a failed apply, want the untouched 60", got.TTL)
	}
}

// Tokens and the admin account are node-local. A snapshot must not reach them.
func TestApplySnapshotLeavesTokensAndAdminAlone(t *testing.T) {
	s := open(t)
	if _, err := s.PutToken(Token{Label: "cli", Hash: "hash-1"}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAdminPassword("argon2-hash"); err != nil {
		t.Fatal(err)
	}
	if err := s.ApplySnapshot(SnapshotInput{Settings: baseSettings()}); err != nil {
		t.Fatal(err)
	}
	toks, err := s.Tokens()
	if err != nil {
		t.Fatal(err)
	}
	if len(toks) != 1 {
		t.Fatalf("Tokens() = %d after apply, want 1", len(toks))
	}
	hash, err := s.AdminHash()
	if err != nil {
		t.Fatal(err)
	}
	if hash != "argon2-hash" {
		t.Fatalf("AdminHash() = %q, want the untouched hash", hash)
	}
}

// A list body is node-local: each node downloads its own. Applying a snapshot
// must not blank out a body this node already has.
func TestApplySnapshotKeepsLocalListBodies(t *testing.T) {
	s := open(t)
	id, err := s.PutBlacklistList(BlacklistList{Name: "steven",
		URL: "https://example.test/hosts", Format: "hosts"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetBlacklistSnapshot(id, []string{"ads.example"}, 0, "etag-1", "", 1); err != nil {
		t.Fatal(err)
	}
	err = s.ApplySnapshot(SnapshotInput{
		Settings: baseSettings(),
		Lists: []BlacklistList{{Name: "steven",
			URL: "https://example.test/hosts", Format: "hosts", Enabled: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	lists, err := s.BlacklistLists()
	if err != nil {
		t.Fatal(err)
	}
	if len(lists) != 1 {
		t.Fatalf("BlacklistLists() = %d, want 1", len(lists))
	}
	if len(lists[0].Snapshot) != 1 || lists[0].Snapshot[0] != "ads.example" {
		t.Fatalf("list body = %v after apply, want the locally downloaded body", lists[0].Snapshot)
	}
}
