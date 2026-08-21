package adminapi

import (
	"errors"
	"net/http"
	"slices"

	"github.com/yoshiofthewire/kydns-server/internal/settings"
	"github.com/yoshiofthewire/kydns-server/internal/store"
)

// settingsDTO is the wire form. It is a flat document because that is what a
// form posts and what a person editing JSON expects. yaml tags mirror the
// json ones: import decodes with yaml.Unmarshal (JSON is a YAML subset), and
// a field with no yaml tag falls back to its lowercased Go name instead of
// its snake_case json name, which would silently blank every field on import.
type settingsDTO struct {
	PrivateDomain     string   `json:"private_domain" yaml:"private_domain"`
	ReverseZones      []string `json:"reverse_zones" yaml:"reverse_zones"`
	Upstreams         []string `json:"upstreams" yaml:"upstreams"`
	AllowQuery        []string `json:"allow_query" yaml:"allow_query"`
	AllowTailscale    bool     `json:"allow_tailscale" yaml:"allow_tailscale"`
	TTL               int      `json:"ttl" yaml:"ttl"`
	CacheMinTTL       int      `json:"cache_min_ttl" yaml:"cache_min_ttl"`
	CacheMaxTTL       int      `json:"cache_max_ttl" yaml:"cache_max_ttl"`
	NegativeMaxTTL    int      `json:"negative_max_ttl" yaml:"negative_max_ttl"`
	CacheEntries      int      `json:"cache_entries" yaml:"cache_entries"`
	LogQueries        bool     `json:"log_queries" yaml:"log_queries"`
	LogClientIP       bool     `json:"log_client_ip" yaml:"log_client_ip"`
	DHCPLeaseFile     string   `json:"dhcp_lease_file" yaml:"dhcp_lease_file"`
	DiscoveryInterval int      `json:"discovery_interval" yaml:"discovery_interval"`
	HealthInterval    int      `json:"health_interval" yaml:"health_interval"`
	HealthTimeout     int      `json:"health_timeout" yaml:"health_timeout"`
	HealthWorkers     int      `json:"health_workers" yaml:"health_workers"`

	// The built-in DHCP server. Node-local, like dhcp_lease_file beside it:
	// never replicated, but carried in an export, which is an operator
	// restoring this node rather than a peer being handed a configuration.
	DHCPEnabled      bool   `json:"dhcp_enabled" yaml:"dhcp_enabled"`
	DHCPInterface    string `json:"dhcp_interface" yaml:"dhcp_interface"`
	DHCPRangeStart   string `json:"dhcp_range_start" yaml:"dhcp_range_start"`
	DHCPRangeEnd     string `json:"dhcp_range_end" yaml:"dhcp_range_end"`
	DHCPGateway      string `json:"dhcp_gateway" yaml:"dhcp_gateway"`
	DHCPLeaseSeconds int    `json:"dhcp_lease_seconds" yaml:"dhcp_lease_seconds"`
	DHCPSecondaryDNS string `json:"dhcp_secondary_dns" yaml:"dhcp_secondary_dns"`
	DHCPAllowForeign bool   `json:"dhcp_allow_foreign" yaml:"dhcp_allow_foreign"`

	// ConfirmPublic authorises one public allow_query prefix for this request
	// only. It is never stored and never returned, and it has no yaml tag: a
	// field absent from the export document must never round-trip through it.
	ConfirmPublic string `json:"confirm_public,omitempty" yaml:"-"`
}

func toSettingsDTO(v store.Settings) settingsDTO {
	// Slices are cloned, not aliased: v may be the live holder's snapshot, and
	// json.Unmarshal reuses a slice's existing backing array in place when
	// decoding a PATCH body onto it, which would silently overwrite the
	// running settings before validation even sees them.
	return settingsDTO{
		PrivateDomain: v.PrivateDomain, ReverseZones: slices.Clone(v.ReverseZones),
		Upstreams: slices.Clone(v.Upstreams), AllowQuery: slices.Clone(v.AllowQuery),
		AllowTailscale: v.AllowTailscale, TTL: v.TTL,
		CacheMinTTL: v.CacheMinTTL, CacheMaxTTL: v.CacheMaxTTL,
		NegativeMaxTTL: v.NegativeMaxTTL, CacheEntries: v.CacheEntries,
		LogQueries: v.LogQueries, LogClientIP: v.LogClientIP,
		DHCPLeaseFile: v.DHCPLeaseFile, DiscoveryInterval: v.DiscoveryInterval,
		HealthInterval: v.HealthInterval, HealthTimeout: v.HealthTimeout,
		HealthWorkers: v.HealthWorkers,
		DHCPEnabled:   v.DHCPEnabled, DHCPInterface: v.DHCPInterface,
		DHCPRangeStart: v.DHCPRangeStart, DHCPRangeEnd: v.DHCPRangeEnd,
		DHCPGateway: v.DHCPGateway, DHCPLeaseSeconds: v.DHCPLeaseSeconds,
		DHCPSecondaryDNS: v.DHCPSecondaryDNS, DHCPAllowForeign: v.DHCPAllowForeign,
	}
}

func fromSettingsDTO(d settingsDTO) store.Settings {
	return store.Settings{
		PrivateDomain: d.PrivateDomain, ReverseZones: d.ReverseZones,
		Upstreams: d.Upstreams, AllowQuery: d.AllowQuery,
		AllowTailscale: d.AllowTailscale, TTL: d.TTL,
		CacheMinTTL: d.CacheMinTTL, CacheMaxTTL: d.CacheMaxTTL,
		NegativeMaxTTL: d.NegativeMaxTTL, CacheEntries: d.CacheEntries,
		LogQueries: d.LogQueries, LogClientIP: d.LogClientIP,
		DHCPLeaseFile: d.DHCPLeaseFile, DiscoveryInterval: d.DiscoveryInterval,
		HealthInterval: d.HealthInterval, HealthTimeout: d.HealthTimeout,
		HealthWorkers: d.HealthWorkers,
		DHCPEnabled:   d.DHCPEnabled, DHCPInterface: d.DHCPInterface,
		DHCPRangeStart: d.DHCPRangeStart, DHCPRangeEnd: d.DHCPRangeEnd,
		DHCPGateway: d.DHCPGateway, DHCPLeaseSeconds: d.DHCPLeaseSeconds,
		DHCPSecondaryDNS: d.DHCPSecondaryDNS, DHCPAllowForeign: d.DHCPAllowForeign,
	}
}

func (a *API) requireSettings(w http.ResponseWriter) bool {
	if a.settings == nil {
		writeErr(w, http.StatusServiceUnavailable, "unavailable", "", "settings are not wired")
		return false
	}
	return true
}

func (a *API) getSettings(w http.ResponseWriter, _ *http.Request) {
	if !a.requireSettings(w) {
		return
	}
	cur, err := a.settings.Get()
	if err != nil {
		writeRegistryErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toSettingsDTO(cur))
}

// patchSettings merges onto the current settings: an absent field keeps its
// value, an explicit empty list clears one.
func (a *API) patchSettings(w http.ResponseWriter, r *http.Request) {
	if !a.requireSettings(w) {
		return
	}
	cur, err := a.settings.Get()
	if err != nil {
		writeRegistryErr(w, err)
		return
	}
	d := toSettingsDTO(cur)
	if !decode(w, r, &d) {
		return
	}
	if err := a.settings.Set(fromSettingsDTO(d), d.ConfirmPublic); err != nil {
		writeSettingsErr(w, err)
		return
	}
	out, err := a.settings.Get()
	if err != nil {
		writeRegistryErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toSettingsDTO(out))
}

// writeSettingsErr turns a FieldError into the same shape every other endpoint
// returns, so a client highlights the input without special-casing settings.
func writeSettingsErr(w http.ResponseWriter, err error) {
	var fe settings.FieldError
	if errors.As(err, &fe) {
		writeErr(w, http.StatusBadRequest, "invalid", fe.Field, fe.Msg)
		return
	}
	writeRegistryErr(w, err)
}
