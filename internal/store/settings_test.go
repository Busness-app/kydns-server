package store

import (
	"database/sql"
	"reflect"
	"testing"
)

func TestSettingsRoundTripsDHCPFields(t *testing.T) {
	s := open(t)
	v, _, err := s.Settings()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	v.DHCPEnabled = true
	v.DHCPInterface = "eth0"
	v.DHCPRangeStart = "192.168.1.128"
	v.DHCPRangeEnd = "192.168.1.254"
	v.DHCPGateway = "192.168.1.1"
	v.DHCPLeaseSeconds = 86400
	v.DHCPSecondaryDNS = "192.168.1.3"
	v.DHCPAllowForeign = true
	if err := s.PutSettings(v); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, ok, err := s.Settings()
	if err != nil || !ok {
		t.Fatalf("read back: %v ok=%v", err, ok)
	}
	if !reflect.DeepEqual(got, v) {
		t.Fatalf("round trip = %+v, want %+v", got, v)
	}
}

func TestDHCPSettingsDoNotBumpConfigVersion(t *testing.T) {
	s := open(t)
	v, _, err := s.Settings()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := s.PutSettings(v); err != nil {
		t.Fatalf("seed write: %v", err)
	}
	before, err := s.ConfigVersion()
	if err != nil {
		t.Fatalf("version: %v", err)
	}

	v.DHCPEnabled = true
	v.DHCPInterface = "eth0"
	v.DHCPAllowForeign = true
	if err := s.PutSettings(v); err != nil {
		t.Fatalf("write: %v", err)
	}

	after, err := s.ConfigVersion()
	if err != nil {
		t.Fatalf("version: %v", err)
	}
	if after != before {
		t.Fatalf("config version moved from %d to %d; DHCP settings are node-local and must not replicate", before, after)
	}
}

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

func TestRenameInZone(t *testing.T) {
	for _, tc := range []struct {
		name, from, to, want string
		moved                bool
	}{
		{"printer.home.arpa.", "home.arpa.", "lan.example.", "printer.lan.example.", true},
		{"home.arpa.", "home.arpa.", "lan.example.", "lan.example.", true},
		{"deep.sub.home.arpa.", "home.arpa.", "lan.example.", "deep.sub.lan.example.", true},
		{"PRINTER.HOME.ARPA.", "home.arpa.", "lan.example.", "printer.lan.example.", true},
		// Outside the zone: the operator's own name, left alone.
		{"nas.other.example.", "home.arpa.", "lan.example.", "nas.other.example.", false},
		// A name that merely ends in the same letters is not in the zone.
		{"nothome.arpa.", "home.arpa.", "lan.example.", "nothome.arpa.", false},
		{"printer.home.arpa.", "home.arpa.", "home.arpa.", "printer.home.arpa.", false},
	} {
		got, moved := RenameInZone(tc.name, tc.from, tc.to)
		if got != tc.want || moved != tc.moved {
			t.Errorf("RenameInZone(%q, %q, %q) = (%q, %v), want (%q, %v)",
				tc.name, tc.from, tc.to, got, moved, tc.want, tc.moved)
		}
	}
}

// Renaming the private zone moves the records with it. A record left behind
// would be outside the zone the server serves and would answer nothing.
func TestPutSettingsRenamingZoneMovesRecords(t *testing.T) {
	st := open(t)
	base := Settings{
		PrivateDomain: "home.arpa", TTL: 60, CacheMinTTL: 5, CacheMaxTTL: 3600,
		NegativeMaxTTL: 300, CacheEntries: 100, DiscoveryInterval: 30,
		HealthInterval: 30, HealthTimeout: 5, HealthWorkers: 8,
	}
	if err := st.PutSettings(base); err != nil {
		t.Fatal(err)
	}
	for _, r := range []Record{
		{Name: "printer.home.arpa.", Type: "A", Value: "10.0.0.5"},
		{Name: "www.home.arpa.", Type: "CNAME", Value: "nas.home.arpa."},
		{Name: "off.other.example.", Type: "A", Value: "10.0.0.6"},
		{Name: "5.0.0.10.in-addr.arpa.", Type: "PTR", Value: "printer.home.arpa."},
	} {
		if _, err := st.PutRecord(r); err != nil {
			t.Fatal(err)
		}
	}

	next := base
	next.PrivateDomain = "lan.example"
	moved, err := st.PutSettingsRenamingZone(next, "home.arpa", "lan.example")
	if err != nil {
		t.Fatalf("PutSettingsRenamingZone: %v", err)
	}
	if moved != 3 {
		t.Errorf("moved = %d, want the three records that were in the zone", moved)
	}

	got := map[string]string{}
	recs, err := st.Records()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range recs {
		got[r.Name] = r.Value
	}
	want := map[string]string{
		"printer.lan.example.":   "10.0.0.5",
		"www.lan.example.":       "nas.lan.example.", // the CNAME target moved too
		"off.other.example.":     "10.0.0.6",         // outside the zone, untouched
		"5.0.0.10.in-addr.arpa.": "printer.lan.example.",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("records after the rename =\n%v\nwant\n%v", got, want)
	}

	// The settings row and the records have to land together.
	v, ok, err := st.Settings()
	if err != nil || !ok {
		t.Fatalf("Settings: %v %v", ok, err)
	}
	if v.PrivateDomain != "lan.example" {
		t.Errorf("private_domain = %q, want the new domain", v.PrivateDomain)
	}
}
