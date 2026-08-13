// Package config loads the KyDNS process configuration. It holds process
// concerns only — listeners, upstreams, the ACL. Views are registry data.
package config

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/yoshiofthewire/kydns-server/internal/store"
	"github.com/yoshiofthewire/kydns-server/internal/upstream"
	"gopkg.in/yaml.v3"
)

// TailscaleCGNAT is the range added to the ACL by DNSConfig.AllowTailscale.
const TailscaleCGNAT = "100.64.0.0/10"

// defaultAllowQuery is loopback plus RFC1918 and ULA. CGNAT is deliberately
// absent: it is gated behind AllowTailscale.
var defaultAllowQuery = []string{
	"127.0.0.0/8", "::1/128",
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
	"169.254.0.0/16", "fe80::/10", "fc00::/7",
}

type Config struct {
	DNS       DNSConfig       `yaml:"dns"`
	Admin     AdminConfig     `yaml:"admin"`
	Discovery DiscoveryConfig `yaml:"discovery"`
	Health    HealthConfig    `yaml:"health"`
	DataDir   string          `yaml:"data_dir"`

	// explicitEmptyDomain records that the operator wrote an empty
	// private_domain, which must fail rather than silently defaulting.
	explicitEmptyDomain bool
}

type DNSConfig struct {
	Listen         string   `yaml:"listen"`
	PrivateDomain  string   `yaml:"private_domain"`
	ReverseZones   []string `yaml:"reverse_zones"`
	Upstreams      []string `yaml:"upstreams"`
	AllowQuery     []string `yaml:"allow_query"`
	AllowTailscale bool     `yaml:"allow_tailscale"`
	TTL            int      `yaml:"ttl"`
	CacheMinTTL    int      `yaml:"cache_min_ttl"`
	CacheMaxTTL    int      `yaml:"cache_max_ttl"`
	NegativeMaxTTL int      `yaml:"negative_max_ttl"`
	CacheEntries   int      `yaml:"cache_entries"`
	LogQueries     bool     `yaml:"log_queries"`
	LogClientIP    bool     `yaml:"log_client_ip"`
}

type AdminConfig struct {
	Listen string `yaml:"listen"`
}

// DiscoveryConfig is off unless DHCPLeaseFile is set: KyDNS does not guess at
// a lease file path.
type DiscoveryConfig struct {
	DHCPLeaseFile string `yaml:"dhcp_lease_file"`
	Interval      int    `yaml:"interval"`
}

type HealthConfig struct {
	Interval int `yaml:"interval"`
	Timeout  int `yaml:"timeout"`
	Workers  int `yaml:"workers"`
}

// domainProbe distinguishes an absent private_domain from an explicitly empty
// one, which plain unmarshalling into a string cannot.
type domainProbe struct {
	DNS struct {
		PrivateDomain *string `yaml:"private_domain"`
	} `yaml:"dns"`
}

// Load reads path, applies defaults, and validates. It returns an error rather
// than a partially usable Config: the process must never run half-configured.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var c Config
	if err := yaml.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	var probe domainProbe
	_ = yaml.Unmarshal(raw, &probe)
	c.explicitEmptyDomain = probe.DNS.PrivateDomain != nil && *probe.DNS.PrivateDomain == ""

	c.applyDefaults()
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return &c, nil
}

func (c *Config) applyDefaults() {
	set := func(p *string, v string) {
		if *p == "" {
			*p = v
		}
	}
	setInt := func(p *int, v int) {
		if *p == 0 {
			*p = v
		}
	}
	set(&c.DNS.Listen, ":53")
	set(&c.Admin.Listen, "127.0.0.1:8053")
	if c.DNS.PrivateDomain == "" && !c.explicitEmptyDomain {
		c.DNS.PrivateDomain = "home.arpa"
	}
	setInt(&c.DNS.TTL, 60)
	setInt(&c.DNS.CacheMinTTL, 5)
	setInt(&c.DNS.CacheMaxTTL, 3600)
	setInt(&c.DNS.NegativeMaxTTL, 300)
	setInt(&c.DNS.CacheEntries, 10000)
	setInt(&c.Discovery.Interval, 30)
	setInt(&c.Health.Interval, 30)
	setInt(&c.Health.Timeout, 5)
	setInt(&c.Health.Workers, 8)
	if len(c.DNS.Upstreams) == 0 {
		c.DNS.Upstreams = []string{"tls://1.1.1.1:853", "tls://9.9.9.9:853"}
	}
	if len(c.DNS.AllowQuery) == 0 {
		c.DNS.AllowQuery = append([]string(nil), defaultAllowQuery...)
	}
}

func (c *Config) validate() error {
	if c.DataDir == "" {
		return errors.New("data_dir is required")
	}
	if c.DNS.PrivateDomain == "" {
		return errors.New("dns.private_domain must not be empty")
	}
	for _, s := range c.DNS.AllowQuery {
		if _, err := netip.ParsePrefix(s); err != nil {
			return fmt.Errorf("dns.allow_query %q: %w", s, err)
		}
	}
	for _, s := range c.DNS.ReverseZones {
		if _, err := netip.ParsePrefix(s); err != nil {
			return fmt.Errorf("dns.reverse_zones %q: %w", s, err)
		}
	}
	if _, err := upstream.ParseAll(c.DNS.Upstreams); err != nil {
		return fmt.Errorf("dns.upstreams: %w", err)
	}
	if c.DNS.CacheMinTTL > c.DNS.CacheMaxTTL {
		return errors.New("dns.cache_min_ttl exceeds dns.cache_max_ttl")
	}
	return nil
}

// PrivateFQDN returns the private domain as a lowercased FQDN with a trailing
// dot, the form miekg/dns uses throughout.
func (c *Config) PrivateFQDN() string {
	return strings.ToLower(c.DNS.PrivateDomain) + "."
}

// SeedSettings is the config file's contribution to a fresh database: every
// key that has moved into the store, with defaults already applied. It is read
// once, on the first run. After that the database owns these values and edits
// to the file do nothing.
func (c *Config) SeedSettings() store.Settings {
	return store.Settings{
		PrivateDomain:     c.DNS.PrivateDomain,
		ReverseZones:      append([]string(nil), c.DNS.ReverseZones...),
		Upstreams:         append([]string(nil), c.DNS.Upstreams...),
		AllowQuery:        append([]string(nil), c.DNS.AllowQuery...),
		AllowTailscale:    c.DNS.AllowTailscale,
		TTL:               c.DNS.TTL,
		CacheMinTTL:       c.DNS.CacheMinTTL,
		CacheMaxTTL:       c.DNS.CacheMaxTTL,
		NegativeMaxTTL:    c.DNS.NegativeMaxTTL,
		CacheEntries:      c.DNS.CacheEntries,
		LogQueries:        c.DNS.LogQueries,
		LogClientIP:       c.DNS.LogClientIP,
		DHCPLeaseFile:     c.Discovery.DHCPLeaseFile,
		DiscoveryInterval: c.Discovery.Interval,
		HealthInterval:    c.Health.Interval,
		HealthTimeout:     c.Health.Timeout,
		HealthWorkers:     c.Health.Workers,
	}
}
