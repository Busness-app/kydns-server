package store

import "testing"

func TestConfigVersionStartsAtZero(t *testing.T) {
	s := open(t)
	v, err := s.ConfigVersion()
	if err != nil {
		t.Fatal(err)
	}
	if v != 0 {
		t.Fatalf("ConfigVersion() = %d, want 0", v)
	}
}

func TestServiceWriteBumpsConfigVersion(t *testing.T) {
	s := open(t)
	before, err := s.ConfigVersion()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.PutService(Service{Name: "kypost"}); err != nil {
		t.Fatal(err)
	}
	after, err := s.ConfigVersion()
	if err != nil {
		t.Fatal(err)
	}
	if after <= before {
		t.Fatalf("ConfigVersion() = %d after a service write, want > %d", after, before)
	}
}

// A token is node-local. Replicating on a token write would wake every replica
// for a change none of them will ever receive.
func TestTokenWriteDoesNotBumpConfigVersion(t *testing.T) {
	s := open(t)
	before, err := s.ConfigVersion()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.PutToken(Token{Label: "cli", Hash: "abc"}); err != nil {
		t.Fatal(err)
	}
	after, err := s.ConfigVersion()
	if err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("ConfigVersion() = %d after a token write, want %d", after, before)
	}
}

func TestRecordDeleteBumpsConfigVersion(t *testing.T) {
	s := open(t)
	id, err := s.PutRecord(Record{Name: "nas.home.arpa.", Type: "A", Value: "192.168.1.5"})
	if err != nil {
		t.Fatal(err)
	}
	before, err := s.ConfigVersion()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteRecord(id); err != nil {
		t.Fatal(err)
	}
	after, err := s.ConfigVersion()
	if err != nil {
		t.Fatal(err)
	}
	if after <= before {
		t.Fatalf("ConfigVersion() = %d after a delete, want > %d", after, before)
	}
}

// A blacklist refresh writes the downloaded body and its cache validators on
// every poll. Those are node-local, so they must not look like a config change.
func TestBlacklistBodyWriteDoesNotBumpConfigVersion(t *testing.T) {
	s := open(t)
	id, err := s.PutBlacklistList(BlacklistList{Name: "steven", URL: "https://example.test/hosts", Format: "hosts"})
	if err != nil {
		t.Fatal(err)
	}
	before, err := s.ConfigVersion()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetBlacklistSnapshot(id, []string{"ads.example"}, 0, "etag-1", "Mon, 01 Jan 2029 00:00:00 GMT", 0); err != nil {
		t.Fatal(err)
	}
	after, err := s.ConfigVersion()
	if err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("ConfigVersion() = %d after a snapshot write, want %d", after, before)
	}
}

// The node-local settings keys must not wake replicas either.
func TestSettingsSplitBumpsOnlyForReplicatedKeys(t *testing.T) {
	s := open(t)
	base := Settings{PrivateDomain: "home.arpa", TTL: 60, CacheMinTTL: 5,
		CacheMaxTTL: 3600, NegativeMaxTTL: 300, CacheEntries: 10000,
		DiscoveryInterval: 30, HealthInterval: 30, HealthTimeout: 5, HealthWorkers: 8}
	if err := s.PutSettings(base); err != nil {
		t.Fatal(err)
	}

	before, err := s.ConfigVersion()
	if err != nil {
		t.Fatal(err)
	}
	local := base
	local.LogQueries = true
	if err := s.PutSettings(local); err != nil {
		t.Fatal(err)
	}
	mid, err := s.ConfigVersion()
	if err != nil {
		t.Fatal(err)
	}
	if mid != before {
		t.Fatalf("ConfigVersion() = %d after a log_queries write, want %d", mid, before)
	}

	shared := local
	shared.TTL = 120
	if err := s.PutSettings(shared); err != nil {
		t.Fatal(err)
	}
	after, err := s.ConfigVersion()
	if err != nil {
		t.Fatal(err)
	}
	if after <= mid {
		t.Fatalf("ConfigVersion() = %d after a ttl write, want > %d", after, mid)
	}
}
