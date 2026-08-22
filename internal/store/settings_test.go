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

// The replica write path. It exists so a DHCP save cannot revert what the
// background pull applied in between, which means it must move the eight
// columns and nothing else.
func TestPutDHCPSettingsTouchesOnlyTheDHCPColumns(t *testing.T) {
	s := open(t)
	before := baseSettings()
	if err := s.PutSettings(before); err != nil {
		t.Fatal(err)
	}

	// Everything the caller might be carrying a stale copy of, changed.
	v := before
	v.PrivateDomain = "should.not.land"
	v.Upstreams = []string{"udp://9.9.9.9:53"}
	v.AllowQuery = []string{"0.0.0.0/0"}
	v.ReverseZones = []string{"10.0.0.0/8"}
	v.TTL, v.CacheEntries, v.HealthWorkers = 1, 1, 1
	v.LogQueries, v.AllowTailscale = !before.LogQueries, !before.AllowTailscale
	v.DHCPLeaseFile = "/should/not/land"
	v.DHCPEnabled, v.DHCPInterface = true, "eth0"
	v.DHCPRangeStart, v.DHCPRangeEnd = "192.168.1.100", "192.168.1.200"
	v.DHCPGateway, v.DHCPLeaseSeconds = "192.168.1.1", 3600
	v.DHCPSecondaryDNS, v.DHCPAllowForeign = "192.168.1.2", true
	if err := s.PutDHCPSettings(v); err != nil {
		t.Fatal(err)
	}

	got, ok, err := s.Settings()
	if err != nil || !ok {
		t.Fatal(err)
	}
	// The eight landed.
	if !got.DHCPEnabled || got.DHCPInterface != "eth0" || got.DHCPRangeStart != "192.168.1.100" ||
		got.DHCPRangeEnd != "192.168.1.200" || got.DHCPGateway != "192.168.1.1" ||
		got.DHCPLeaseSeconds != 3600 || got.DHCPSecondaryDNS != "192.168.1.2" || !got.DHCPAllowForeign {
		t.Fatalf("the DHCP settings did not land: %+v", got)
	}
	// Nothing else did. Compared whole, so a column added later is covered.
	want := before
	want.DHCPEnabled, want.DHCPInterface = got.DHCPEnabled, got.DHCPInterface
	want.DHCPRangeStart, want.DHCPRangeEnd = got.DHCPRangeStart, got.DHCPRangeEnd
	want.DHCPGateway, want.DHCPLeaseSeconds = got.DHCPGateway, got.DHCPLeaseSeconds
	want.DHCPSecondaryDNS, want.DHCPAllowForeign = got.DHCPSecondaryDNS, got.DHCPAllowForeign
	if !reflect.DeepEqual(got, want) {
		t.Errorf("a column outside the eight moved:\ngot  %+v\nwant %+v", got, want)
	}
}

// Ruling P22a, at the layer that decides it. The pull and a replica's DHCP save
// are not ordered against each other, so both orderings have to be correct.
func TestADHCPSaveAndAPullSurviveEitherOrder(t *testing.T) {
	dhcp := func(v Settings) Settings {
		v.DHCPEnabled, v.DHCPInterface = true, "eth0"
		v.DHCPRangeStart, v.DHCPRangeEnd = "192.168.1.100", "192.168.1.200"
		v.DHCPGateway, v.DHCPLeaseSeconds = "192.168.1.1", 3600
		return v
	}
	pulled := baseSettings()
	pulled.Upstreams = []string{"udp://9.9.9.9:53"}
	pulled.TTL = 900

	for _, saveFirst := range []bool{true, false} {
		s := open(t)
		if err := s.PutSettings(baseSettings()); err != nil {
			t.Fatal(err)
		}
		save := func() {
			if err := s.PutDHCPSettings(dhcp(baseSettings())); err != nil {
				t.Fatal(err)
			}
		}
		pull := func() {
			if err := s.ApplySnapshot(SnapshotInput{Settings: pulled}); err != nil {
				t.Fatal(err)
			}
		}
		if saveFirst {
			save()
			pull()
		} else {
			pull()
			save()
		}
		got, _, err := s.Settings()
		if err != nil {
			t.Fatal(err)
		}
		if !got.DHCPEnabled || got.DHCPInterface != "eth0" {
			t.Errorf("saveFirst=%v: the DHCP save was lost: %+v", saveFirst, got)
		}
		if got.TTL != 900 || len(got.Upstreams) != 1 || got.Upstreams[0] != "udp://9.9.9.9:53" {
			t.Errorf("saveFirst=%v: the pulled configuration was reverted: %+v", saveFirst, got)
		}
	}
}

// A silent no-op would tell the operator a save landed when the row it was
// meant for does not exist.
func TestPutDHCPSettingsWithNoRowSaysSo(t *testing.T) {
	s := open(t)
	if err := s.PutDHCPSettings(baseSettings()); err == nil {
		t.Fatal("writing the DHCP settings with no settings row reported success")
	}
}

// The DHCP settings are node-local, so writing them is not a configuration
// change any peer should hear about.
func TestPutDHCPSettingsDoesNotBumpConfigVersion(t *testing.T) {
	s := open(t)
	if err := s.PutSettings(baseSettings()); err != nil {
		t.Fatal(err)
	}
	before, err := s.ConfigVersion()
	if err != nil {
		t.Fatal(err)
	}
	v := baseSettings()
	v.DHCPEnabled, v.DHCPInterface = true, "eth0"
	if err := s.PutDHCPSettings(v); err != nil {
		t.Fatal(err)
	}
	after, err := s.ConfigVersion()
	if err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Errorf("config_version %d -> %d: a node-local write was replicated", before, after)
	}
}
