package policy

import "github.com/yoshiofthewire/kydns-server/internal/store"

// The values the query log's policy field can take, alongside a list name.
const (
	PolicyForwarded = "forwarded"
	PolicyAllow     = "allow"
	PolicyDeny      = "deny"
)

// defaultBlockTTL is how long a client should cache a block when settings
// carry no value.
const defaultBlockTTL = 60

// Decision is what the policy says about one forwarded name. Policy is the
// query log's policy field: "deny", "allow", a list name, or "forwarded".
type Decision struct {
	Blocked bool
	Policy  string
	TTL     uint32
}

type namedSet struct {
	name string
	set  *Set
}

// Snapshot is an immutable policy. The DNS hot path reads one with no lock;
// every change builds a new one.
type Snapshot struct {
	enabled bool
	ttl     uint32
	deny    *Set
	allow   *Set
	lists   []namedSet
}

// Build assembles a snapshot. Disabled lists are left out entirely rather than
// carried and skipped, so a disabled list costs nothing on the hot path.
func Build(set store.BlacklistSettings, lists []store.BlacklistList, rules []store.BlacklistRule) *Snapshot {
	ttl := set.BlockTTL
	if ttl <= 0 {
		ttl = defaultBlockTTL
	}
	s := &Snapshot{enabled: set.Enabled, ttl: uint32(ttl)}
	var deny, allow []string
	for _, r := range rules {
		switch r.Kind {
		case PolicyDeny:
			deny = append(deny, r.Domain)
		case PolicyAllow:
			allow = append(allow, r.Domain)
		}
	}
	s.deny, s.allow = NewSet(deny), NewSet(allow)
	for _, l := range lists {
		if !l.Enabled || len(l.Snapshot) == 0 {
			continue
		}
		s.lists = append(s.lists, namedSet{name: l.Name, set: NewSet(l.Snapshot)})
	}
	return s
}

// Decide applies the precedence the spec fixes: an explicit deny, then an
// explicit allow, then the enabled lists. A name it cannot normalize is
// forwarded: filtering never turns a strange query into a failure.
func (s *Snapshot) Decide(name string) Decision {
	if s == nil || !s.enabled {
		return Decision{Policy: PolicyForwarded}
	}
	n, err := Normalize(name)
	if err != nil {
		return Decision{Policy: PolicyForwarded}
	}
	if s.deny.Match(n) {
		return Decision{Blocked: true, Policy: PolicyDeny, TTL: s.ttl}
	}
	if s.allow.Match(n) {
		return Decision{Policy: PolicyAllow}
	}
	for _, l := range s.lists {
		if l.set.Match(n) {
			return Decision{Blocked: true, Policy: l.name, TTL: s.ttl}
		}
	}
	return Decision{Policy: PolicyForwarded}
}
