package config

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/yoshiofthewire/kydns-server/internal/store"
)

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "kydns.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadAppliesDefaults(t *testing.T) {
	c, err := Load(write(t, "data_dir: /var/lib/kydns\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.DNS.Listen != ":53" {
		t.Errorf("Listen = %q, want :53", c.DNS.Listen)
	}
	if c.DNS.PrivateDomain != "home.arpa" {
		t.Errorf("PrivateDomain = %q, want home.arpa", c.DNS.PrivateDomain)
	}
	if c.DNS.TTL != 60 {
		t.Errorf("TTL = %d, want 60", c.DNS.TTL)
	}
	if c.Admin.Listen != "127.0.0.1:8053" {
		t.Errorf("Admin.Listen = %q, want 127.0.0.1:8053", c.Admin.Listen)
	}
	if c.DNS.AllowTailscale {
		t.Error("AllowTailscale = true, want false by default")
	}
	if len(c.DNS.AllowQuery) == 0 {
		t.Error("AllowQuery is empty, want private-range defaults")
	}
}

func TestLoadRejects(t *testing.T) {
	for name, body := range map[string]string{
		"no data dir":      "dns:\n  listen: \":53\"\n",
		"bad dns listen":   "data_dir: /tmp/x\ndns:\n  listen: \"53\"\n",
		"bad admin listen": "data_dir: /tmp/x\nadmin:\n  listen: \"localhost\"\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(write(t, body)); err == nil {
				t.Fatal("Load() error = nil, want error")
			}
		})
	}
}

// Replication is opt-in. A file that never mentions it leaves this node
// standalone.
func TestReplicationOffByDefault(t *testing.T) {
	c, err := Load(write(t, "data_dir: /tmp/kydns\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Replication.Listen != "" || c.Replication.Primary != "" {
		t.Fatalf("Replication = %+v, want both empty", c.Replication)
	}
}

// A node that is both primary and replica has no defined behaviour. Refusing
// at startup is the only honest answer.
func TestBothReplicationKeysIsAnError(t *testing.T) {
	_, err := Load(write(t, "data_dir: /tmp/kydns\nreplication:\n  listen: \":8443\"\n  primary: \"10.0.0.2:8443\"\n"))
	if err == nil {
		t.Fatal("a node configured as both primary and replica started")
	}
	for _, want := range []string{"replication.listen", "replication.primary"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %s", err, want)
		}
	}
}

func TestReplicationAddressesAreValidated(t *testing.T) {
	for name, body := range map[string]string{
		"bad listen":  "data_dir: /tmp/x\nreplication:\n  listen: \"not-an-address\"\n",
		"bad primary": "data_dir: /tmp/x\nreplication:\n  primary: \"not-an-address\"\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(write(t, body)); err == nil {
				t.Fatal("an unparseable replication address was accepted")
			}
		})
	}
}

// The primary is pasted into a URL and dialled on a loop, so a value that only
// half parses has to be refused at startup rather than logged five seconds at
// a time. A hostname is fine: the pin is the peer's key, not its name.
func TestPrimaryMustBeAHostAndAPort(t *testing.T) {
	for name, primary := range map[string]string{
		"a url":          "https://10.0.0.2:8443",
		"a path":         "10.0.0.2:8443/replica",
		"a service name": "10.0.0.2:https",
		"no host":        ":8443",
		"port zero":      "10.0.0.2:0",
		"port too high":  "10.0.0.2:65536",
	} {
		t.Run(name, func(t *testing.T) {
			body := "data_dir: /tmp/x\nreplication:\n  primary: \"" + primary + "\"\n"
			if _, err := Load(write(t, body)); err == nil {
				t.Fatalf("primary %q was accepted", primary)
			}
		})
	}
	for name, primary := range map[string]string{
		"an ip":      "10.0.0.2:8443",
		"a hostname": "primary.home.arpa:8443",
		"ipv6":       "[fd00::2]:8443",
		"port one":   "10.0.0.2:1",
		"port 65535": "10.0.0.2:65535",
	} {
		t.Run(name, func(t *testing.T) {
			body := "data_dir: /tmp/x\nreplication:\n  primary: \"" + primary + "\"\n"
			if _, err := Load(write(t, body)); err != nil {
				t.Fatalf("primary %q was refused: %v", primary, err)
			}
		})
	}
}

// Replication is file-owned, like data_dir and the two listen addresses. A
// key that leaked into the seed would become database state an operator could
// not remove by editing the file.
func TestReplicationIsNotSeeded(t *testing.T) {
	c, err := Load(write(t, "data_dir: /tmp/x\nreplication:\n  primary: \"10.0.0.2:8443\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	seed := c.SeedSettings()
	if strings.Contains(fmt.Sprintf("%+v", seed), "8443") {
		t.Errorf("a replication key reached the seeded settings: %+v", seed)
	}
}

// The database owns these keys after the first run, so the file must not be
// able to refuse a start over them. An operator tidying their YAML on an
// installed server must not lose DNS.
func TestLoadIgnoresMovedKeys(t *testing.T) {
	for name, body := range map[string]string{
		"bad allow_query":  "data_dir: /tmp/x\ndns:\n  allow_query: [\"totally bogus\"]\n",
		"bad reverse zone": "data_dir: /tmp/x\ndns:\n  reverse_zones: [\"192.168.1.0\"]\n",
		"bad upstream":     "data_dir: /tmp/x\ndns:\n  upstreams: [\"1.1.1.1:no\"]\n",
		"inverted ttls":    "data_dir: /tmp/x\ndns:\n  cache_min_ttl: 900\n  cache_max_ttl: 60\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(write(t, body)); err != nil {
				t.Fatalf("Load() error = %v, want the moved key to be ignored", err)
			}
		})
	}
}

func TestAllowTailscaleExplicit(t *testing.T) {
	c, err := Load(write(t, "data_dir: /tmp/x\ndns:\n  allow_tailscale: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !c.DNS.AllowTailscale {
		t.Error("AllowTailscale = false, want true")
	}
}

// Encryption is the default. An operator who does nothing gets a private path
// to the upstream.
func TestDefaultUpstreamsAreEncrypted(t *testing.T) {
	c, err := Load(write(t, "data_dir: /tmp/x\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.DNS.Upstreams) == 0 {
		t.Fatal("no default upstreams")
	}
	for _, u := range c.DNS.Upstreams {
		if !strings.HasPrefix(u, "tls://") {
			t.Errorf("default upstream %q is not encrypted", u)
		}
	}
}

// The file seeds the database on first run, so every moved key has to survive
// the trip. A key missing here is a setting that silently reverts to its
// default the first time an operator upgrades.
func TestSeedSettingsCarriesEveryMovedKey(t *testing.T) {
	path := write(t, `
data_dir: /tmp/kydns
dns:
  private_domain: lab.example
  reverse_zones: ["192.168.1.0/24"]
  upstreams: ["tls://9.9.9.9:853"]
  allow_query: ["192.168.0.0/16"]
  allow_tailscale: true
  ttl: 90
  cache_min_ttl: 10
  cache_max_ttl: 1800
  negative_max_ttl: 120
  cache_entries: 500
  log_queries: true
  log_client_ip: true
discovery:
  dhcp_lease_file: /var/lib/misc/dnsmasq.leases
  interval: 15
health:
  interval: 45
  timeout: 3
  workers: 4
`)
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got := c.SeedSettings()
	want := store.Settings{
		PrivateDomain:     "lab.example",
		ReverseZones:      []string{"192.168.1.0/24"},
		Upstreams:         []string{"tls://9.9.9.9:853"},
		AllowQuery:        []string{"192.168.0.0/16"},
		AllowTailscale:    true,
		TTL:               90,
		CacheMinTTL:       10,
		CacheMaxTTL:       1800,
		NegativeMaxTTL:    120,
		CacheEntries:      500,
		LogQueries:        true,
		LogClientIP:       true,
		DHCPLeaseFile:     "/var/lib/misc/dnsmasq.leases",
		DiscoveryInterval: 15,
		HealthInterval:    45,
		HealthTimeout:     3,
		HealthWorkers:     4,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("seed differs\n got %+v\nwant %+v", got, want)
	}
}

// A file with nothing but data_dir must seed the same defaults the code
// applies, so a bare install and a documented install agree.
func TestSeedSettingsUsesDefaults(t *testing.T) {
	c, err := Load(write(t, "data_dir: /tmp/kydns\n"))
	if err != nil {
		t.Fatal(err)
	}
	got := c.SeedSettings()
	if got.PrivateDomain != "home.arpa" || got.TTL != 60 || got.HealthWorkers != 8 {
		t.Errorf("defaults did not reach the seed: %+v", got)
	}
	if len(got.Upstreams) == 0 || len(got.AllowQuery) == 0 {
		t.Error("the seeded upstreams or ACL are empty, which would refuse every query")
	}
}

func TestEnvOverridesFileValues(t *testing.T) {
	t.Setenv("KYDNS_DATA_DIR", "/srv/kydns")
	t.Setenv("KYDNS_DNS_LISTEN", "0.0.0.0:5353")
	t.Setenv("KYDNS_ADMIN_LISTEN", "0.0.0.0:8053")
	t.Setenv("KYDNS_REPLICATION_LISTEN", "0.0.0.0:8443")

	c, err := Load(write(t, "data_dir: /var/lib/kydns\ndns:\n  listen: \":53\"\nadmin:\n  listen: \"127.0.0.1:8053\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.DataDir != "/srv/kydns" {
		t.Errorf("DataDir = %q, want /srv/kydns", c.DataDir)
	}
	if c.DNS.Listen != "0.0.0.0:5353" {
		t.Errorf("DNS.Listen = %q, want 0.0.0.0:5353", c.DNS.Listen)
	}
	if c.Admin.Listen != "0.0.0.0:8053" {
		t.Errorf("Admin.Listen = %q, want 0.0.0.0:8053", c.Admin.Listen)
	}
	if c.Replication.Listen != "0.0.0.0:8443" {
		t.Errorf("Replication.Listen = %q, want 0.0.0.0:8443", c.Replication.Listen)
	}
}

// Tested apart from the four above, because a node is a primary or a replica
// and never both.
func TestEnvSetsTheReplicaPrimary(t *testing.T) {
	t.Setenv("KYDNS_REPLICATION_PRIMARY", "10.0.0.2:8443")

	c, err := Load(write(t, "data_dir: /tmp/x\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Replication.Primary != "10.0.0.2:8443" {
		t.Errorf("Replication.Primary = %q, want 10.0.0.2:8443", c.Replication.Primary)
	}
}

// The file holds one key and the environment the other, so an error naming
// only the two keys would send the operator grepping a file that has one.
func TestBothReplicationKeysAcrossSourcesNamesEachSource(t *testing.T) {
	t.Setenv("KYDNS_REPLICATION_PRIMARY", "10.0.0.2:8443")

	_, err := Load(write(t, "data_dir: /tmp/x\nreplication:\n  listen: \"0.0.0.0:8443\"\n"))
	if err == nil {
		t.Fatal("a node configured as both primary and replica started")
	}
	for _, want := range []string{
		"replication.listen (from the config file)",
		"replication.primary (from KYDNS_REPLICATION_PRIMARY)",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
}

// An unRAID template field left blank must not demote a working primary to
// standalone, so an empty variable is not an override.
func TestEmptyEnvIsNotAnOverride(t *testing.T) {
	t.Setenv("KYDNS_REPLICATION_LISTEN", "")

	c, err := Load(write(t, "data_dir: /tmp/x\nreplication:\n  listen: \"0.0.0.0:8443\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Replication.Listen != "0.0.0.0:8443" {
		t.Errorf("Replication.Listen = %q, want the file value 0.0.0.0:8443", c.Replication.Listen)
	}
	if got := c.EnvOverrides(); len(got) != 0 {
		t.Errorf("EnvOverrides() = %v, want none", got)
	}
}

// The environment can set a key the file never mentions at all, not just one
// the file sets to something else.
func TestEnvSetsAKeyTheFileOmits(t *testing.T) {
	t.Setenv("KYDNS_ADMIN_LISTEN", "0.0.0.0:8053")

	c, err := Load(write(t, "data_dir: /tmp/x\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Admin.Listen != "0.0.0.0:8053" {
		t.Errorf("Admin.Listen = %q, want 0.0.0.0:8053", c.Admin.Listen)
	}
}

func TestEnvOverridesAreRecorded(t *testing.T) {
	t.Setenv("KYDNS_DNS_LISTEN", "0.0.0.0:5353")
	t.Setenv("KYDNS_REPLICATION_LISTEN", "0.0.0.0:8443")

	c, err := Load(write(t, "data_dir: /tmp/x\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"KYDNS_DNS_LISTEN", "KYDNS_REPLICATION_LISTEN"}
	if got := c.EnvOverrides(); !reflect.DeepEqual(got, want) {
		t.Errorf("EnvOverrides() = %v, want %v", got, want)
	}
}

// A trailing space typed into a web form field, unlike YAML, is not stripped
// on the way in. Left untrimmed it would point data_dir at a path that looks
// right and is not, silently opening a fresh database.
func TestEnvValueIsTrimmed(t *testing.T) {
	t.Setenv("KYDNS_DATA_DIR", " /srv/kydns \n")

	c, err := Load(write(t, "data_dir: /tmp/x\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.DataDir != "/srv/kydns" {
		t.Errorf("DataDir = %q, want /srv/kydns", c.DataDir)
	}
}

// Whitespace-only is the same as empty: it must not be recorded as an
// override or replace the file value.
func TestEnvWhitespaceOnlyIsNotAnOverride(t *testing.T) {
	t.Setenv("KYDNS_DATA_DIR", "   ")

	c, err := Load(write(t, "data_dir: /tmp/x\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.DataDir != "/tmp/x" {
		t.Errorf("DataDir = %q, want the file value /tmp/x", c.DataDir)
	}
	if got := c.EnvOverrides(); len(got) != 0 {
		t.Errorf("EnvOverrides() = %v, want none", got)
	}
}

// The overlay runs before validate, so a bad address fails the same way from
// either source.
func TestEnvAddressesAreValidated(t *testing.T) {
	for name, env := range map[string][2]string{
		"bad admin listen":       {"KYDNS_ADMIN_LISTEN", "localhost"},
		"bad replication listen": {"KYDNS_REPLICATION_LISTEN", "not-an-address"},
		"primary as a url path":  {"KYDNS_REPLICATION_PRIMARY", "10.0.0.2:8443/replica"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(env[0], env[1])
			if _, err := Load(write(t, "data_dir: /tmp/x\n")); err == nil {
				t.Fatalf("Load() error = nil, want error for %s=%s", env[0], env[1])
			}
		})
	}
}
