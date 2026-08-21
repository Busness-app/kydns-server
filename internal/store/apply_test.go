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

// A list matched by name but pointed at a new URL must not keep serving the
// old source's body or ETag: the body belongs to the URL, not the name. This
// is what pins the by-name key, unlike TestApplySnapshotKeepsLocalListBodies
// above, which reuses the same URL and so would pass under a by-URL key too.
func TestApplySnapshotClearsBodyWhenURLChanges(t *testing.T) {
	s := open(t)
	id, err := s.PutBlacklistList(BlacklistList{Name: "steven",
		URL: "https://old.example/hosts", Format: "hosts"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetBlacklistSnapshot(id, []string{"ads.example"}, 0, "etag-1", "last-mod-1", 1); err != nil {
		t.Fatal(err)
	}
	err = s.ApplySnapshot(SnapshotInput{
		Settings: baseSettings(),
		Lists: []BlacklistList{{Name: "steven",
			URL: "https://new.example/hosts", Format: "hosts", Enabled: true}},
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
	l := lists[0]
	if l.URL != "https://new.example/hosts" {
		t.Fatalf("URL = %q, want the new URL", l.URL)
	}
	if len(l.Snapshot) != 0 || l.ETag != "" || l.LastModified != "" || l.LastAttemptAt != 0 || l.LastOKAt != 0 {
		t.Fatalf("list = %+v after a URL change, want body/etag/refresh clock cleared", l)
	}
}

// A list absent from the snapshot no longer exists on the primary and must
// be removed, not left behind as an orphan.
func TestApplySnapshotDeletesListsAbsentFromSnapshot(t *testing.T) {
	s := open(t)
	if _, err := s.PutBlacklistList(BlacklistList{Name: "gone",
		URL: "https://example.test/gone", Format: "hosts"}); err != nil {
		t.Fatal(err)
	}
	err := s.ApplySnapshot(SnapshotInput{Settings: baseSettings()})
	if err != nil {
		t.Fatal(err)
	}
	lists, err := s.BlacklistLists()
	if err != nil {
		t.Fatal(err)
	}
	if len(lists) != 0 {
		t.Fatalf("BlacklistLists() = %+v, want none after the list left the snapshot", lists)
	}
}

// A list new to this node has never been downloaded here, so it must start
// with no body rather than inheriting one from an unrelated existing row.
func TestApplySnapshotNewListStartsWithEmptyBody(t *testing.T) {
	s := open(t)
	err := s.ApplySnapshot(SnapshotInput{
		Settings: baseSettings(),
		Lists: []BlacklistList{{Name: "fresh",
			URL: "https://example.test/fresh", Format: "hosts", Enabled: true}},
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
	if len(lists[0].Snapshot) != 0 || lists[0].ETag != "" {
		t.Fatalf("new list = %+v, want an empty body and no etag", lists[0])
	}
}

// Blacklist settings and rules are replicated too, not just visited on the
// failure path.
func TestApplySnapshotAppliesBlacklistSettingsAndRules(t *testing.T) {
	s := open(t)
	err := s.ApplySnapshot(SnapshotInput{
		Settings:  baseSettings(),
		Blacklist: BlacklistSettings{Enabled: false, BlockTTL: 120},
		Rules:     []BlacklistRule{{Kind: "deny", Domain: "ads.example"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	bset, err := s.BlacklistSettings()
	if err != nil {
		t.Fatal(err)
	}
	if bset.Enabled || bset.BlockTTL != 120 {
		t.Fatalf("BlacklistSettings() = %+v, want {Enabled:false BlockTTL:120}", bset)
	}
	rules, err := s.BlacklistRules()
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[0].Domain != "ads.example" {
		t.Fatalf("BlacklistRules() = %+v, want exactly the deny rule", rules)
	}
}

// dhcp_lease_file, discovery_interval, log_queries, log_client_ip and every
// dhcp_* field are node-local and must survive an apply even when the
// incoming Settings carries different values for them (e.g. a caller
// forwarding a pulled document verbatim, or a primary's own DHCP config
// arriving inside a snapshot pulled for an unrelated replicated change).
func TestApplySnapshotPreservesNodeLocalSettings(t *testing.T) {
	s := open(t)
	local := baseSettings()
	local.DHCPLeaseFile = "/var/lib/dhcp/dhcpd.leases"
	local.DiscoveryInterval = 45
	local.LogQueries = true
	local.LogClientIP = true
	local.DHCPEnabled = true
	local.DHCPInterface = "eth0"
	local.DHCPRangeStart = "192.168.1.128"
	local.DHCPRangeEnd = "192.168.1.254"
	local.DHCPGateway = "192.168.1.1"
	local.DHCPLeaseSeconds = 43200
	local.DHCPSecondaryDNS = "192.168.1.3"
	local.DHCPAllowForeign = true
	if err := s.PutSettings(local); err != nil {
		t.Fatal(err)
	}

	incoming := baseSettings()
	incoming.DHCPLeaseFile = "/should/not/land"
	incoming.DiscoveryInterval = 999
	incoming.LogQueries = false
	incoming.LogClientIP = false
	incoming.DHCPEnabled = true
	incoming.DHCPInterface = "wlan0"
	incoming.DHCPRangeStart = "10.0.0.128"
	incoming.DHCPRangeEnd = "10.0.0.254"
	incoming.DHCPGateway = "10.0.0.1"
	incoming.DHCPLeaseSeconds = 7200
	incoming.DHCPSecondaryDNS = "10.0.0.3"
	incoming.DHCPAllowForeign = false
	if err := s.ApplySnapshot(SnapshotInput{Settings: incoming}); err != nil {
		t.Fatal(err)
	}

	got, _, err := s.Settings()
	if err != nil {
		t.Fatal(err)
	}
	if got.DHCPLeaseFile != local.DHCPLeaseFile || got.DiscoveryInterval != local.DiscoveryInterval ||
		!got.LogQueries || !got.LogClientIP {
		t.Fatalf("Settings() = %+v after apply, want node-local fields untouched", got)
	}
	if got.DHCPInterface != local.DHCPInterface || got.DHCPRangeStart != local.DHCPRangeStart ||
		got.DHCPRangeEnd != local.DHCPRangeEnd || got.DHCPGateway != local.DHCPGateway ||
		got.DHCPLeaseSeconds != local.DHCPLeaseSeconds || got.DHCPSecondaryDNS != local.DHCPSecondaryDNS ||
		got.DHCPAllowForeign != local.DHCPAllowForeign {
		t.Fatalf("Settings() = %+v after apply, want DHCP fields untouched by the incoming snapshot", got)
	}
}
