package policy

import "strings"

// Set is an immutable suffix-matching domain set. A rule for ads.example
// matches that name and its subdomains, but never badads.example: the walk
// only ever cuts at a label boundary.
type Set struct{ m map[string]struct{} }

// NewSet builds a set from already-normalized domains.
func NewSet(domains []string) *Set {
	m := make(map[string]struct{}, len(domains))
	for _, d := range domains {
		m[d] = struct{}{}
	}
	return &Set{m: m}
}

// Match reports whether name, itself already normalized, is in the set or is a
// subdomain of something in it.
func (s *Set) Match(name string) bool {
	if s == nil || len(s.m) == 0 {
		return false
	}
	for {
		if _, ok := s.m[name]; ok {
			return true
		}
		i := strings.IndexByte(name, '.')
		if i < 0 {
			return false
		}
		name = name[i+1:]
	}
}

func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return len(s.m)
}
