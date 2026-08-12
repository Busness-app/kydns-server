package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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

func TestEffectiveAllowQueryAddsCGNATOnlyWhenEnabled(t *testing.T) {
	off, err := Load(write(t, "data_dir: /tmp/x\n"))
	if err != nil {
		t.Fatal(err)
	}
	list, err := off.EffectiveAllowQuery()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range list {
		if p.String() == TailscaleCGNAT {
			t.Error("CGNAT range present with allow_tailscale off")
		}
	}

	on, err := Load(write(t, "data_dir: /tmp/x\ndns:\n  allow_tailscale: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	list, err = on.EffectiveAllowQuery()
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, p := range list {
		if p.String() == TailscaleCGNAT {
			found = true
		}
	}
	if !found {
		t.Error("CGNAT range missing with allow_tailscale on")
	}
}
