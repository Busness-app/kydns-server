package app

import (
	"log/slog"
	"sync"
	"time"

	"github.com/yoshiofthewire/kydns-server/internal/discovery"
	"github.com/yoshiofthewire/kydns-server/internal/discovery/dhcp"
	"github.com/yoshiofthewire/kydns-server/internal/dnsserver"
	"github.com/yoshiofthewire/kydns-server/internal/health"
	"github.com/yoshiofthewire/kydns-server/internal/registry"
	"github.com/yoshiofthewire/kydns-server/internal/settings"
	"github.com/yoshiofthewire/kydns-server/internal/zone"
)

// liveComponents is every running piece a settings change fans out to. It
// exists as a named type, rather than a closure inside Serve, so a test can
// build one against real components and call Apply directly — proving the
// fan-out actually reaches them, not just that Service.Set returned nil.
type liveComponents struct {
	acl           *dnsserver.ACL
	forwarder     *dnsserver.Forwarder
	cache         *dnsserver.Cache
	dnsSrv        *dnsserver.Server
	authoritative *dnsserver.Authoritative
	checker       *health.Checker
	poller        *discovery.Poller // nil only in tests that do not build one
	zoneHolder    *zone.Holder
	registry      *registry.Registry
	logger        *slog.Logger
	dhcp          *dhcpRunner // nil in tests that do not build one

	// prevUpstreams tracks what the forwarder was last told, so a change
	// against the previous upstream list flushes stale cached answers.
	prevUpstreams []string

	// mu serializes the fan-out. A settings save and a replication pull both
	// reach Apply, from different goroutines, and prevUpstreams has one writer.
	mu sync.Mutex
}

// Apply fans a validated, already-built settings snapshot out to every live
// component. Every value here is already validated and built, so no swap
// below can fail.
func (l *liveComponents) Apply(s *settings.Snapshot) {
	l.mu.Lock()
	defer l.mu.Unlock()
	// The private zone first: the snapshot rebuild at the end of this function
	// builds names under it, and the records were already moved into it by the
	// same write that produced this snapshot.
	if zoneChanged(l.authoritative.Zone(), s.Raw.PrivateDomain) {
		old := l.authoritative.Zone()
		l.authoritative.SetZone(s.Raw.PrivateDomain)
		l.registry.SetZone(s.Raw.PrivateDomain)
		// Cached answers are keyed by name, and every name under the old zone is
		// now wrong. Nothing else evicts them, so they would be served until
		// their TTL ran out.
		l.cache.Flush()
		l.logger.Info("private zone renamed", "from", old, "to", l.authoritative.Zone())
	}
	l.acl.Replace(s.AllowQuery)
	l.forwarder.Replace(s.Upstreams)
	flushOnUpstreamChange(l.cache, l.prevUpstreams, s.Raw.Upstreams, l.logger)
	l.prevUpstreams = s.Raw.Upstreams
	l.cache.Retune(s.Raw.CacheEntries, s.Raw.CacheMinTTL, s.Raw.CacheMaxTTL, s.Raw.NegativeMaxTTL)
	l.dnsSrv.SetLogging(s.Raw.LogQueries, s.Raw.LogClientIP)
	l.authoritative.SetTTL(uint32(s.Raw.TTL))
	l.authoritative.SetReverseZones(s.ReverseZones)
	l.checker.Reconfigure(
		time.Duration(s.Raw.HealthInterval)*time.Second,
		time.Duration(s.Raw.HealthTimeout)*time.Second,
		s.Raw.HealthWorkers)
	// The lease source follows the settings: built-in, lease file, or neither.
	// Reconcile is idempotent, so an unchanged configuration is a no-op rather
	// than a restart of a working listener.
	if l.dhcp != nil {
		l.dhcp.Reconcile(s.Raw)
	}
	if l.poller != nil {
		// Gated on what is actually running, not on what was asked for: a
		// build that refused leaves nothing owning the source, and the old
		// lease file would otherwise keep feeding the zone forever.
		running := false
		if l.dhcp != nil {
			running, _ = l.dhcp.Status()
		}
		if !running {
			if s.Raw.DHCPLeaseFile != "" {
				l.poller.SetSource(&dhcp.DnsmasqSource{Path: s.Raw.DHCPLeaseFile})
			} else {
				l.poller.SetSource(nil)
			}
		}
		l.poller.SetInterval(time.Duration(s.Raw.DiscoveryInterval) * time.Second)
	}
	// Reverse zones are an input to the zone snapshot, so it has to be rebuilt.
	if err := l.zoneHolder.Rebuild(); err != nil {
		l.logger.Error("snapshot rebuild after a settings change failed, still serving the previous snapshot", "error", err)
	}
	l.logger.Info("settings applied")
}
