package config

import (
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

func TestPrivateFQDN(t *testing.T) {
	c, err := Load(write(t, "data_dir: /tmp/x\ndns:\n  private_domain: lab.internal\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.PrivateFQDN(); got != "lab.internal." {
		t.Errorf("PrivateFQDN() = %q, want lab.internal.", got)
	}
}

func TestLoadRejects(t *testing.T) {
	for name, body := range map[string]string{
		"no data dir":      "dns:\n  listen: \":53\"\n",
		"bad allow_query":  "data_dir: /tmp/x\ndns:\n  allow_query: [\"not-a-cidr\"]\n",
		"bad reverse zone": "data_dir: /tmp/x\ndns:\n  reverse_zones: [\"192.168.1.0\"]\n",
		"bad upstream":     "data_dir: /tmp/x\ndns:\n  upstreams: [\"1.1.1.1:no\"]\n",
		"empty domain":     "data_dir: /tmp/x\ndns:\n  private_domain: \"\"\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(write(t, body)); err == nil {
				t.Fatal("Load() error = nil, want error")
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

func TestUpstreamValidation(t *testing.T) {
	body := func(u string) string {
		return "data_dir: /tmp/x\ndns:\n  upstreams: [\"" + u + "\"]\n"
	}
	for _, good := range []string{
		"tls://1.1.1.1:853", "https://9.9.9.9/dns-query", "udp://192.168.1.1:53", "1.1.1.1:53",
	} {
		if _, err := Load(write(t, body(good))); err != nil {
			t.Errorf("upstreams [%q] rejected: %v", good, err)
		}
	}
	for _, bad := range []string{"tls://dns.quad9.net:853", "quic://1.1.1.1:853", "1.1.1.1:no"} {
		if _, err := Load(write(t, body(bad))); err == nil {
			t.Errorf("upstreams [%q] accepted, want a rejection", bad)
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
