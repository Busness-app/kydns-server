package store

import (
	"database/sql"
	"reflect"
	"testing"
)

func TestSettingsRoundTrip(t *testing.T) {
	st := open(t)

	if _, ok, err := st.Settings(); err != nil {
		t.Fatalf("Settings on a fresh database: %v", err)
	} else if ok {
		t.Fatal("a fresh database reports a settings row; it must report none so the seed can run")
	}

	want := Settings{
		PrivateDomain:     "home.arpa",
		ReverseZones:      []string{"192.168.1.0/24", "10.0.0.0/8"},
		Upstreams:         []string{"tls://1.1.1.1:853", "tls://9.9.9.9:853"},
		AllowQuery:        []string{"127.0.0.0/8", "192.168.0.0/16"},
		AllowTailscale:    true,
		TTL:               60,
		CacheMinTTL:       5,
		CacheMaxTTL:       3600,
		NegativeMaxTTL:    300,
		CacheEntries:      10000,
		LogQueries:        true,
		LogClientIP:       false,
		DHCPLeaseFile:     "/var/lib/misc/dnsmasq.leases",
		DiscoveryInterval: 30,
		HealthInterval:    30,
		HealthTimeout:     5,
		HealthWorkers:     8,
	}
	if err := st.PutSettings(want); err != nil {
		t.Fatalf("PutSettings: %v", err)
	}

	got, ok, err := st.Settings()
	if err != nil || !ok {
		t.Fatalf("Settings after write: ok=%v err=%v", ok, err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("round trip differs\n got %+v\nwant %+v", got, want)
	}
	// Upstreams are tried in order, so order is data, not presentation.
	if got.Upstreams[0] != "tls://1.1.1.1:853" {
		t.Errorf("upstream order lost: %v", got.Upstreams)
	}
}

// A second write must update the single row rather than fail or accumulate.
func TestPutSettingsReplaces(t *testing.T) {
	st := open(t)
	if err := st.PutSettings(Settings{PrivateDomain: "a.example", TTL: 10}); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := st.PutSettings(Settings{PrivateDomain: "b.example", TTL: 20}); err != nil {
		t.Fatalf("second write: %v", err)
	}
	got, _, err := st.Settings()
	if err != nil {
		t.Fatal(err)
	}
	if got.PrivateDomain != "b.example" || got.TTL != 20 {
		t.Errorf("second write did not replace the row: %+v", got)
	}
}

// An empty list must survive as empty rather than come back as [""].
func TestSettingsEmptyLists(t *testing.T) {
	st := open(t)
	if err := st.PutSettings(Settings{PrivateDomain: "home.arpa"}); err != nil {
		t.Fatal(err)
	}
	got, _, err := st.Settings()
	if err != nil {
		t.Fatal(err)
	}
	if len(got.ReverseZones) != 0 {
		t.Errorf("empty reverse_zones came back as %#v", got.ReverseZones)
	}
}

// A database created before the settings table must gain it on the next Open,
// not fail and not wedge every future Open.
func TestSettingsMigrationOnOldDatabase(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/old.db"

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	// A minimal pre-settings database: schema version 1, no settings table.
	if _, err := db.Exec(schema); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DROP TABLE settings; PRAGMA user_version = 1`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	st, err := Open(path)
	if err != nil {
		t.Fatalf("Open on a pre-settings database: %v", err)
	}
	defer st.Close()
	if _, _, err := st.Settings(); err != nil {
		t.Fatalf("settings table missing after migration: %v", err)
	}
}
