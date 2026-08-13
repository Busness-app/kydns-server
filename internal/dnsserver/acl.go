// Package dnsserver answers DNS queries from the zone snapshot and forwards
// everything else.
package dnsserver

import (
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/yoshiofthewire/kydns-server/internal/settings"
)

var cgnat = netip.MustParsePrefix(settings.TailscaleCGNAT)

// RefusalStats is a point-in-time read of the ACL counters. It carries counts
// and a timestamp only — never a source address — so it costs nothing against
// the logging policy and does not depend on the client-IP flag.
type RefusalStats struct {
	Total     uint64
	CGNAT     uint64
	LastCGNAT int64 // unix seconds, 0 if never
}

// ACL is the query allow-list. It is default-closed: an empty allow list
// refuses everything.
type ACL struct {
	allowed   atomic.Pointer[[]netip.Prefix]
	total     atomic.Uint64
	cgnat     atomic.Uint64
	lastCGNAT atomic.Int64
	now       func() time.Time // swappable for tests
}

func NewACL(allowed []netip.Prefix) *ACL {
	a := &ACL{now: time.Now}
	a.Replace(allowed)
	return a
}

// Replace swaps the allow list. Readers on the query path load a pointer, so a
// swap never blocks a query and never shows a half-built list. Refusal
// counters describe the process and survive it.
func (a *ACL) Replace(allowed []netip.Prefix) {
	masked := make([]netip.Prefix, 0, len(allowed))
	for _, p := range allowed {
		masked = append(masked, p.Masked())
	}
	a.allowed.Store(&masked)
}

// Allow reports whether addr may query, counting refusals. Refusals are
// otherwise invisible, which is the worst possible thing to debug, so the
// counters feed /stats and the dashboard banner.
func (a *ACL) Allow(addr netip.Addr) bool {
	if !addr.IsValid() {
		a.total.Add(1)
		return false
	}
	addr = addr.Unmap()
	for _, p := range *a.allowed.Load() {
		if p.Contains(addr) {
			return true
		}
	}
	a.total.Add(1)
	if cgnat.Contains(addr) {
		a.cgnat.Add(1)
		a.lastCGNAT.Store(a.now().Unix())
	}
	return false
}

func (a *ACL) Stats() RefusalStats {
	return RefusalStats{
		Total:     a.total.Load(),
		CGNAT:     a.cgnat.Load(),
		LastCGNAT: a.lastCGNAT.Load(),
	}
}

// RecentCGNATRefusal drives condition 1 of the dashboard banner.
func (a *ACL) RecentCGNATRefusal(within time.Duration) bool {
	last := a.lastCGNAT.Load()
	if last == 0 {
		return false
	}
	return a.now().Sub(time.Unix(last, 0)) < within
}
