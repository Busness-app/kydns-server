package store

// View is a named match rule. Subnets are CIDR strings; a CIDR may belong to
// only one view, enforced by a unique index.
type View struct {
	Name    string
	Subnets []string
}

// Address is one address for a service. View == "" means every view.
type Address struct {
	ID      int64
	Address string
	View    string
}

type Service struct {
	ID            int64
	Name          string
	Addresses     []Address
	Aliases       []string
	CheckURL      string
	CheckInsecure bool

	// ProxyAddress is where clients are sent when RouteViaProxy is on. The
	// two are separate so routing can be turned off for a moment without
	// discarding the address.
	ProxyAddress  string
	RouteViaProxy bool
}

// Record is a manually authored record. View == "" means every view.
type Record struct {
	ID    int64
	Name  string
	Type  string
	Value string
	View  string
}

type Token struct {
	ID         int64
	Label      string
	Hash       string
	CreatedAt  int64
	LastUsedAt int64
}

// BlacklistSettings is the global filtering policy. Filtering is on by
// default; the toggle disables new blocks without deleting anything.
type BlacklistSettings struct {
	Enabled  bool
	BlockTTL int // seconds a client should cache a block
}

// BlacklistList is one source. Snapshot is the last known-good normalized
// body, and is loaded only where it is needed.
type BlacklistList struct {
	ID              int64
	Name            string
	URL             string
	Format          string
	Description     string
	Enabled         bool
	Builtin         bool
	IntervalSeconds int64
	LastAttemptAt   int64
	LastOKAt        int64
	LastError       string
	ETag            string
	LastModified    string
	EntryCount      int
	SkippedCount    int
	Snapshot        []string
}

// BlacklistRule is one one-off rule. Kind is "allow" or "deny".
type BlacklistRule struct {
	ID     int64
	Kind   string
	Domain string
}

// Settings is the process configuration that lives in the database rather than
// the config file. data_dir and the two listen addresses are not here: they are
// needed before the database is open.
type Settings struct {
	PrivateDomain     string
	ReverseZones      []string
	Upstreams         []string
	AllowQuery        []string
	AllowTailscale    bool
	TTL               int
	CacheMinTTL       int
	CacheMaxTTL       int
	NegativeMaxTTL    int
	CacheEntries      int
	LogQueries        bool
	LogClientIP       bool
	DHCPLeaseFile     string
	DiscoveryInterval int
	HealthInterval    int
	HealthTimeout     int
	HealthWorkers     int

	// DHCP settings drive the built-in server. They are node-local: no cv_
	// trigger names them, so a replica never hears about them, and two DHCP
	// servers on one segment is exactly what that prevents.
	DHCPEnabled      bool
	DHCPInterface    string
	DHCPRangeStart   string
	DHCPRangeEnd     string
	DHCPGateway      string
	DHCPLeaseSeconds int
	DHCPSecondaryDNS string
}

// AdminIdentity holds the admin credentials and linked KySignOn SSO identity.
type AdminIdentity struct {
	PasswordHash string
	SSOSub       string
	SSOUsername  string
	SSOEmail     string
	SSOLinkedAt  int64
	UpdatedAt    int64
}

// SSOSettings holds the KySignOn SSO configuration.
type SSOSettings struct {
	Enabled      bool
	IssuerURL    string
	ClientID     string
	ClientSecret string
}

// DHCPLease is one address the built-in server has handed out. It is stored
// so a restart cannot re-issue an address that is still in use. Times are
// Unix seconds.
type DHCPLease struct {
	MAC       string
	IP        string
	Hostname  string
	ExpiresAt int64
	LastSeen  int64
}
