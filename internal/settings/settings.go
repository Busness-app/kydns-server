package settings

import (
	"net/netip"
	"time"

	"github.com/yoshiofthewire/kydns-server/internal/store"
	"github.com/yoshiofthewire/kydns-server/internal/upstream"
)

// TailscaleCGNAT is the range AllowTailscale adds to the ACL.
const TailscaleCGNAT = "100.64.0.0/10"

// Snapshot is the parsed, immutable form of the settings. Building it is the
// only fallible part of applying a change, so every swap that follows is
// infallible.
type Snapshot struct {
	Raw          store.Settings
	AllowQuery   []netip.Prefix
	ReverseZones []netip.Prefix
	Upstreams    []upstream.Upstream
}

// Build parses v. It is all-or-nothing: any error returns before a caller has
// swapped anything into the running server.
func Build(v store.Settings) (*Snapshot, error) {
	s := &Snapshot{Raw: v}

	allow := append([]string(nil), v.AllowQuery...)
	if v.AllowTailscale {
		allow = append(allow, TailscaleCGNAT)
	}
	for _, c := range allow {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, bad("allow_query", "%q is not a CIDR prefix", c)
		}
		s.AllowQuery = append(s.AllowQuery, p.Masked())
	}
	for _, c := range v.ReverseZones {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, bad("reverse_zones", "%q is not a CIDR prefix", c)
		}
		s.ReverseZones = append(s.ReverseZones, p.Masked())
	}
	ups, err := upstream.NewAll(v.Upstreams, 2*time.Second)
	if err != nil {
		return nil, bad("upstreams", "%s", err)
	}
	s.Upstreams = ups
	return s, nil
}
