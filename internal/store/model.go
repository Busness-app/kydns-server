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
