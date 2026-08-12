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
