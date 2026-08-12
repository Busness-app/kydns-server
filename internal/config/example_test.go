package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// examplePath is the shipped example, two directories up from this package.
const examplePath = "../../kydns.example.yaml"

// dockerPath is the config the image bakes in at /etc/kydns/kydns.yaml.
const dockerPath = "../../kydns.docker.yaml"

// The image's config is what a fresh container runs on with nothing prepared
// on the host, so a broken one is a container that will not start.
func TestDockerConfigLoads(t *testing.T) {
	c, err := Load(dockerPath)
	if err != nil {
		t.Fatalf("kydns.docker.yaml does not load: %v", err)
	}
	if c.DataDir != "/var/lib/kydns" {
		t.Errorf("data_dir is %q, want the volume the image declares", c.DataDir)
	}
	// Loopback here is the container's own, reachable from nowhere. This is
	// the setting the whole file exists to change.
	if strings.HasPrefix(c.Admin.Listen, "127.") || strings.HasPrefix(c.Admin.Listen, "[::1]") {
		t.Errorf("admin.listen is %q; the admin UI would be unreachable", c.Admin.Listen)
	}
	if c.DNS.AllowTailscale {
		t.Error("image config ships with allow_tailscale on; the default must be closed")
	}
	if c.Discovery.DHCPLeaseFile != "" {
		t.Error("image config ships with discovery enabled; it must be opt-in")
	}
}

// The shipped example must actually load. A broken example is worse than none:
// it is the first thing an operator copies.
func TestExampleConfigLoads(t *testing.T) {
	c, err := Load(examplePath)
	if err != nil {
		t.Fatalf("kydns.example.yaml does not load: %v", err)
	}
	if c.DataDir == "" {
		t.Error("example sets no data_dir")
	}
	if len(c.DNS.Upstreams) == 0 {
		t.Error("example sets no upstreams")
	}
	if c.DNS.AllowTailscale {
		t.Error("example ships with allow_tailscale on; the default must be closed")
	}
	if c.Discovery.DHCPLeaseFile != "" {
		t.Error("example ships with discovery enabled; it must be opt-in")
	}
}

// Every documented value must match the code's default, or the example lies.
func TestExampleMatchesDefaults(t *testing.T) {
	example, err := Load(examplePath)
	if err != nil {
		t.Fatal(err)
	}
	minimal := filepath.Join(t.TempDir(), "min.yaml")
	if err := os.WriteFile(minimal, []byte("data_dir: "+example.DataDir+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	def, err := Load(minimal)
	if err != nil {
		t.Fatal(err)
	}

	for name, pair := range map[string][2]any{
		"dns.listen":           {example.DNS.Listen, def.DNS.Listen},
		"dns.private_domain":   {example.DNS.PrivateDomain, def.DNS.PrivateDomain},
		"dns.ttl":              {example.DNS.TTL, def.DNS.TTL},
		"dns.cache_min_ttl":    {example.DNS.CacheMinTTL, def.DNS.CacheMinTTL},
		"dns.cache_max_ttl":    {example.DNS.CacheMaxTTL, def.DNS.CacheMaxTTL},
		"dns.negative_max_ttl": {example.DNS.NegativeMaxTTL, def.DNS.NegativeMaxTTL},
		"dns.cache_entries":    {example.DNS.CacheEntries, def.DNS.CacheEntries},
		"dns.allow_tailscale":  {example.DNS.AllowTailscale, def.DNS.AllowTailscale},
		"dns.log_queries":      {example.DNS.LogQueries, def.DNS.LogQueries},
		"dns.log_client_ip":    {example.DNS.LogClientIP, def.DNS.LogClientIP},
		"admin.listen":         {example.Admin.Listen, def.Admin.Listen},
		"discovery.interval":   {example.Discovery.Interval, def.Discovery.Interval},
		"health.interval":      {example.Health.Interval, def.Health.Interval},
		"health.timeout":       {example.Health.Timeout, def.Health.Timeout},
		"health.workers":       {example.Health.Workers, def.Health.Workers},
	} {
		if pair[0] != pair[1] {
			t.Errorf("%s: example says %v, default is %v", name, pair[0], pair[1])
		}
	}
	if strings.Join(example.DNS.Upstreams, ",") != strings.Join(def.DNS.Upstreams, ",") {
		t.Errorf("dns.upstreams: example %v, default %v", example.DNS.Upstreams, def.DNS.Upstreams)
	}
	if strings.Join(example.DNS.AllowQuery, ",") != strings.Join(def.DNS.AllowQuery, ",") {
		t.Errorf("dns.allow_query: example %v, default %v", example.DNS.AllowQuery, def.DNS.AllowQuery)
	}
}

// Every field the loader understands should appear in the example, so the
// example stays a complete reference as settings are added.
func TestExampleDocumentsEverySetting(t *testing.T) {
	raw, err := os.ReadFile(examplePath)
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	for _, key := range []string{
		"data_dir", "listen", "private_domain", "reverse_zones", "upstreams",
		"allow_query", "allow_tailscale", "ttl", "cache_min_ttl", "cache_max_ttl",
		"negative_max_ttl", "cache_entries", "log_queries", "log_client_ip",
		"dhcp_lease_file", "interval", "timeout", "workers",
	} {
		if !strings.Contains(body, key+":") {
			t.Errorf("kydns.example.yaml does not mention %q", key)
		}
	}
}
