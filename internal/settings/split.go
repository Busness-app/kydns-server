package settings

import "github.com/yoshiofthewire/kydns-server/internal/store"

// MergeReplicated builds the settings a replica should store: shared policy
// from the primary, node-local keys kept from local. The node-local set is
// the same one the config_version triggers omit, and the two must stay in
// step — a key replicated here but not triggered there would never be
// delivered.
func MergeReplicated(local, incoming store.Settings) store.Settings {
	out := incoming
	out.ReverseZones = append([]string(nil), incoming.ReverseZones...)
	out.Upstreams = append([]string(nil), incoming.Upstreams...)
	out.AllowQuery = append([]string(nil), incoming.AllowQuery...)

	out.DHCPLeaseFile = local.DHCPLeaseFile
	out.DiscoveryInterval = local.DiscoveryInterval
	out.LogQueries = local.LogQueries
	out.LogClientIP = local.LogClientIP
	return out
}
