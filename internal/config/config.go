// Package config loads the KyDNS process configuration. It holds process
// concerns only — listeners, upstreams, the ACL. Views are registry data.
package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Busness-app/kydns-server/internal/store"
	"gopkg.in/yaml.v3"
)

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
	// BackupDepositInterval is node-local process policy, populated only from
	// KYDNS_BACKUP_DEPOSIT_INTERVAL. Zero disables scheduled deposits.
	BackupDepositInterval time.Duration `yaml:"-"`
	// BackupDir, BackupKeep and BackupAllowPrivateRecovery are node-local process
	// policy from KYDNS_BACKUP_DIR, KYDNS_BACKUP_KEEP and
	// KYDNS_BACKUP_ALLOW_PRIVATE_RECOVERY. An empty BackupDir means no local copies.
	BackupDir                  string `yaml:"-"`
	BackupKeep                 int    `yaml:"-"`
	BackupAllowPrivateRecovery bool   `yaml:"-"`

	Replication ReplicationConfig `yaml:"replication"`

	// explicitEmptyDomain records that the operator wrote an empty
	// private_domain, which must fail rather than silently defaulting.
	explicitEmptyDomain bool
	// envApplied names the environment variables that replaced a file value,
	// in table order. Startup logs them, and the mutual-exclusion error reads
	// them to say which source each key came from.
	envApplied []string
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

// ReplicationConfig is file-owned because it is needed before the database is
// usable, like data_dir and the two listen addresses. Both keys empty means
// standalone.
type ReplicationConfig struct {
	Listen  string `yaml:"listen"`  // primary: the TLS replication listener
	Primary string `yaml:"primary"` // replica: the primary to follow
}

// overlayEnv replaces file values with the environment. An empty variable is
// skipped rather than treated as an explicit clear: unRAID templates carry
// fields left blank, and clearing on blank would demote a working primary to
// standalone from a field nobody filled in. Turning replication off stays what
// it is — removing the key from the file.
func (c *Config) overlayEnv() {
	// Only the five keys the file still owns at every start are here: every
	// other key seeds a fresh database once, so a variable for it would
	// silently do nothing on a server that has already been configured.
	table := []struct {
		name  string
		field *string
	}{
		{"KYDNS_DATA_DIR", &c.DataDir},
		{"KYDNS_DNS_LISTEN", &c.DNS.Listen},
		{"KYDNS_ADMIN_LISTEN", &c.Admin.Listen},
		{"KYDNS_REPLICATION_LISTEN", &c.Replication.Listen},
		{"KYDNS_REPLICATION_PRIMARY", &c.Replication.Primary},
	}
	for _, o := range table {
		v := strings.TrimSpace(os.Getenv(o.name))
		if v == "" {
			continue
		}
		*o.field = v
		c.envApplied = append(c.envApplied, o.name)
	}
}

// EnvOverrides names the environment variables that replaced a file value.
func (c *Config) EnvOverrides() []string {
	return append([]string(nil), c.envApplied...)
}

// source names where a key's value came from. It exists for the one error that
// involves two keys at once, which would otherwise send an operator grepping a
// file that holds only one of them.
func (c *Config) source(env string) string {
	if slices.Contains(c.envApplied, env) {
		return env
	}
	return "the config file"
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

	c.overlayEnv()
	c.applyDefaults()
	if err := c.applyBackupEnv(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return &c, nil
}

const MinBackupDepositInterval = 15 * time.Minute

func (c *Config) applyBackupEnv() error {
	raw, ok := os.LookupEnv("KYDNS_BACKUP_DEPOSIT_INTERVAL")
	if !ok || strings.TrimSpace(raw) == "" {
		c.BackupDepositInterval = 24 * time.Hour
		return c.applyBackupDestinationEnv()
	}
	d, err := time.ParseDuration(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("KYDNS_BACKUP_DEPOSIT_INTERVAL: %w", err)
	}
	if d < 0 || (d > 0 && d < MinBackupDepositInterval) {
		return fmt.Errorf("KYDNS_BACKUP_DEPOSIT_INTERVAL: %s is below the %s minimum (0 disables)", d, MinBackupDepositInterval)
	}
	c.BackupDepositInterval = d
	return c.applyBackupDestinationEnv()
}

func (c *Config) applyBackupDestinationEnv() error {
	c.BackupKeep = 7
	if v := strings.TrimSpace(os.Getenv("KYDNS_BACKUP_DIR")); v != "" {
		if !filepath.IsAbs(v) {
			return fmt.Errorf("KYDNS_BACKUP_DIR: %q must be an absolute path", v)
		}
		c.BackupDir = v
	}
	if v := strings.TrimSpace(os.Getenv("KYDNS_BACKUP_KEEP")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return fmt.Errorf("KYDNS_BACKUP_KEEP: %q must be a positive integer", v)
		}
		c.BackupKeep = n
	}
	if v := strings.TrimSpace(os.Getenv("KYDNS_BACKUP_ALLOW_PRIVATE_RECOVERY")); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("KYDNS_BACKUP_ALLOW_PRIVATE_RECOVERY: %q must be true or false", v)
		}
		c.BackupAllowPrivateRecovery = b
	}
	return nil
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

// validate checks only the keys the file still owns. Everything else in this
// struct seeds a fresh database once and is ignored afterwards, so refusing to
// start over it would strand an operator who tidied their YAML. A bad seed is
// caught by settings.ValidateStored on the first run instead.
func (c *Config) validate() error {
	if c.DataDir == "" {
		return errors.New("data_dir is required")
	}
	if _, _, err := net.SplitHostPort(c.DNS.Listen); err != nil {
		return fmt.Errorf("dns.listen %q: %w", c.DNS.Listen, err)
	}
	if _, _, err := net.SplitHostPort(c.Admin.Listen); err != nil {
		return fmt.Errorf("admin.listen %q: %w", c.Admin.Listen, err)
	}
	if c.Replication.Listen != "" && c.Replication.Primary != "" {
		return fmt.Errorf("replication.listen (from %s) and replication.primary (from %s) "+
			"are mutually exclusive: a node is a primary or a replica, never both",
			c.source("KYDNS_REPLICATION_LISTEN"), c.source("KYDNS_REPLICATION_PRIMARY"))
	}
	if c.Replication.Listen != "" {
		if _, _, err := net.SplitHostPort(c.Replication.Listen); err != nil {
			return fmt.Errorf("replication.listen %q: %w", c.Replication.Listen, err)
		}
	}
	if c.Replication.Primary != "" {
		if err := dialAddress(c.Replication.Primary); err != nil {
			return fmt.Errorf("replication.primary %q: %w", c.Replication.Primary, err)
		}
	}
	return nil
}

// dialAddress checks a host:port this node will connect to, which the listen
// addresses above are not: a listener with a bad port fails loudly at startup,
// while a primary with one is pasted into a URL and fails on every poll, in a
// log the operator is not reading.
func dialAddress(raw string) error {
	host, port, err := net.SplitHostPort(raw)
	if err != nil {
		return err
	}
	if host == "" {
		return errors.New("needs a host to dial")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		// "8443/replica" lands here: a pasted URL splits into a host and a
		// port that is not a number.
		return fmt.Errorf("port must be a number from 1 to 65535, not %q", port)
	}
	return nil
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
