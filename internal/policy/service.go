package policy

import (
	"context"
	"net/url"
	"strings"

	"github.com/yoshiofthewire/kydns-server/internal/registry"
	"github.com/yoshiofthewire/kydns-server/internal/store"
)

// Refresh interval bounds. The floor keeps a misconfigured list from
// hammering a public source every tick.
const (
	minInterval     = 300
	defaultInterval = 86400
	maxBlockTTL     = 3600
)

// Service is the blacklist application service both transports call.
// Validation lives here so the JSON API, the CLI and the web UI cannot drift.
type Service struct {
	st *store.Store
	h  *Holder
	r  *Refresher
}

func NewService(st *store.Store, h *Holder, r *Refresher) *Service {
	return &Service{st: st, h: h, r: r}
}

func (s *Service) Settings() (store.BlacklistSettings, error) { return s.st.BlacklistSettings() }

// SetSettings applies the global toggle and block TTL, then rebuilds so the
// change takes effect without a restart.
func (s *Service) SetSettings(enabled bool, blockTTL int) error {
	if blockTTL < 1 || blockTTL > maxBlockTTL {
		return registry.Invalid("block_ttl", "block_ttl_range",
			"the block TTL must be between 1 and %d seconds", maxBlockTTL)
	}
	if err := s.st.SetBlacklistSettings(store.BlacklistSettings{Enabled: enabled, BlockTTL: blockTTL}); err != nil {
		return err
	}
	return s.h.Rebuild()
}

// Lists returns list metadata without the downloaded bodies.
func (s *Service) Lists() ([]store.BlacklistList, error) { return s.st.BlacklistListMetas() }

// PutList validates and writes a list definition, then rebuilds. A built-in
// may be enabled, disabled and re-tuned, but never renamed away from its
// manifest entry or re-pointed at a different URL.
func (s *Service) PutList(l store.BlacklistList) (int64, error) {
	l.Name = strings.ToLower(strings.TrimSpace(l.Name))
	l.URL = strings.TrimSpace(l.URL)
	l.Format = strings.ToLower(strings.TrimSpace(l.Format))
	l.Description = strings.TrimSpace(l.Description)

	if l.Name == "" {
		return 0, registry.Invalid("name", "name_required", "a list needs a name")
	}
	if err := validListURL(l.URL); err != nil {
		return 0, err
	}
	if l.Format == "" {
		l.Format = FormatDomains
	}
	if !ValidFormat(l.Format) {
		return 0, registry.Invalid("format", "format_unsupported",
			"format must be %s, %s or %s", FormatDomains, FormatHosts, FormatAdblock)
	}
	if l.IntervalSeconds == 0 {
		l.IntervalSeconds = defaultInterval
	}
	if l.IntervalSeconds < minInterval {
		return 0, registry.Invalid("interval_seconds", "interval_too_short",
			"the refresh interval must be at least %d seconds", minInterval)
	}

	if l.ID != 0 {
		cur, err := s.st.BlacklistListByID(l.ID)
		if err != nil {
			return 0, err
		}
		l.Builtin = cur.Builtin
		if cur.Builtin && (l.URL != cur.URL || l.Name != cur.Name) {
			return 0, registry.Invalid("url", "builtin_immutable",
				"a built-in list keeps its shipped name and URL; disable it instead")
		}
	} else {
		l.Builtin = false // only the manifest seeds built-ins
	}

	id, err := s.st.PutBlacklistList(l)
	if err != nil {
		return 0, err
	}
	return id, s.h.Rebuild()
}

func validListURL(raw string) error {
	if raw == "" {
		return registry.Invalid("url", "url_required", "a list needs a source URL")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return registry.Invalid("url", "url_invalid", "%q is not a URL", raw)
	}
	if u.Scheme != "https" {
		return registry.Invalid("url", "url_not_https",
			"a list URL must be https so the download can be verified")
	}
	if u.Host == "" {
		return registry.Invalid("url", "url_invalid", "%q has no host", raw)
	}
	return nil
}

func (s *Service) DeleteList(id int64) error {
	cur, err := s.st.BlacklistListByID(id)
	if err != nil {
		return err
	}
	if cur.Builtin {
		return registry.Invalid("id", "builtin_immutable",
			"a built-in list cannot be deleted; disable it instead")
	}
	if err := s.st.DeleteBlacklistList(id); err != nil {
		return err
	}
	return s.h.Rebuild()
}

func (s *Service) Rules() ([]store.BlacklistRule, error) { return s.st.BlacklistRules() }

// AddRule normalizes the domain and writes the rule. A duplicate or a
// conflicting rule of the other kind is refused by the store's unique index.
func (s *Service) AddRule(kind, domain string) (int64, error) {
	kind = strings.ToLower(strings.TrimSpace(kind))
	if kind != PolicyAllow && kind != PolicyDeny {
		return 0, registry.Invalid("kind", "kind_invalid", "a rule is either allow or deny")
	}
	n, err := Normalize(domain)
	if err != nil {
		return 0, registry.Invalid("domain", "domain_invalid", "%q is not a domain name", domain)
	}
	id, err := s.st.PutBlacklistRule(store.BlacklistRule{Kind: kind, Domain: n})
	if err != nil {
		return 0, err
	}
	return id, s.h.Rebuild()
}

func (s *Service) DeleteRule(id int64) error {
	if err := s.st.DeleteBlacklistRule(id); err != nil {
		return err
	}
	return s.h.Rebuild()
}

// Refresh downloads one list now, or every enabled list when id is 0.
func (s *Service) Refresh(ctx context.Context, id int64) error {
	if id == 0 {
		return s.r.RefreshAll(ctx)
	}
	return s.r.RefreshList(ctx, id)
}

// Test answers what the live policy would do with a name, without querying it.
func (s *Service) Test(name string) (Decision, error) {
	n, err := Normalize(name)
	if err != nil {
		return Decision{}, registry.Invalid("name", "name_invalid", "%q is not a domain name", name)
	}
	return s.h.Current().Decide(n), nil
}

// Counters reports blocked totals and counts by list. Never by client.
func (s *Service) Counters() (uint64, map[string]uint64) { return s.h.Counters() }
