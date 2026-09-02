// Package zone builds the immutable per-view snapshot the DNS hot path reads.
package zone

import (
	"fmt"
	"net/netip"
	"sort"

	"github.com/Busness-app/kydns-server/internal/store"
)

type entry struct {
	prefix netip.Prefix
	view   string
}

// Matcher resolves a client source address to a view name. Entries are sorted
// by prefix length descending, so the first containing match is the longest.
// A linear scan is right here: homelabs have a handful of views, and a trie
// would cost more code than it saves.
type Matcher struct {
	entries []entry
	names   []string
}

func NewMatcher(views []store.View) (*Matcher, error) {
	m := &Matcher{}
	claimed := map[netip.Prefix]string{}
	for _, v := range views {
		m.names = append(m.names, v.Name)
		for _, c := range v.Subnets {
			p, err := netip.ParsePrefix(c)
			if err != nil {
				return nil, fmt.Errorf("view %q: cidr %q: %w", v.Name, c, err)
			}
			p = p.Masked()
			if other, dup := claimed[p]; dup {
				return nil, fmt.Errorf("cidr %s is claimed by both view %q and view %q", p, other, v.Name)
			}
			claimed[p] = v.Name
			m.entries = append(m.entries, entry{prefix: p, view: v.Name})
		}
	}
	sort.Slice(m.entries, func(i, j int) bool {
		if a, b := m.entries[i].prefix.Bits(), m.entries[j].prefix.Bits(); a != b {
			return a > b
		}
		return m.entries[i].view < m.entries[j].view
	})
	sort.Strings(m.names)
	return m, nil
}

// Match returns the view name for addr, or "" for the default view.
func (m *Matcher) Match(addr netip.Addr) string {
	if !addr.IsValid() {
		return ""
	}
	// A dual-stack UDP listener reports v4 peers as ::ffff:a.b.c.d. Unmap so
	// v4 views match without the operator having to write v6 CIDRs.
	addr = addr.Unmap()
	for _, e := range m.entries {
		if e.prefix.Contains(addr) {
			return e.view
		}
	}
	return ""
}

// Names returns the configured view names, sorted. The default view ("") is
// not included.
func (m *Matcher) Names() []string { return m.names }
