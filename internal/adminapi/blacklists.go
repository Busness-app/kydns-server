package adminapi

import (
	"errors"
	"net/http"
	"strings"

	"github.com/yoshiofthewire/kydns-server/internal/policy"
	"github.com/yoshiofthewire/kydns-server/internal/store"
)

// blacklistListDTO is the wire form of a list. There is nowhere in it to put
// the downloaded body, which is how an export cannot carry one.
type blacklistListDTO struct {
	ID              int64  `json:"id,omitempty" yaml:"-"`
	Name            string `json:"name" yaml:"name"`
	URL             string `json:"url" yaml:"url"`
	Format          string `json:"format" yaml:"format"`
	Description     string `json:"description,omitempty" yaml:"description,omitempty"`
	Enabled         bool   `json:"enabled" yaml:"enabled"`
	Builtin         bool   `json:"builtin,omitempty" yaml:"builtin,omitempty"`
	IntervalSeconds int64  `json:"interval_seconds" yaml:"interval_seconds"`

	// Runtime state, reported but never imported.
	EntryCount    int    `json:"entry_count" yaml:"-"`
	SkippedCount  int    `json:"skipped_count" yaml:"-"`
	LastOKAt      int64  `json:"last_ok_at" yaml:"-"`
	LastAttemptAt int64  `json:"last_attempt_at" yaml:"-"`
	LastError     string `json:"last_error,omitempty" yaml:"-"`
}

type blacklistRuleDTO struct {
	ID     int64  `json:"id,omitempty" yaml:"-"`
	Kind   string `json:"kind" yaml:"kind"`
	Domain string `json:"domain" yaml:"domain"`
}

func toBlacklistListDTO(l store.BlacklistList) blacklistListDTO {
	return blacklistListDTO{
		ID: l.ID, Name: l.Name, URL: l.URL, Format: l.Format, Description: l.Description,
		Enabled: l.Enabled, Builtin: l.Builtin, IntervalSeconds: l.IntervalSeconds,
		EntryCount: l.EntryCount, SkippedCount: l.SkippedCount,
		LastOKAt: l.LastOKAt, LastAttemptAt: l.LastAttemptAt, LastError: l.LastError,
	}
}

func fromBlacklistListDTO(d blacklistListDTO) store.BlacklistList {
	return store.BlacklistList{
		ID: d.ID, Name: d.Name, URL: d.URL, Format: d.Format, Description: d.Description,
		Enabled: d.Enabled, Builtin: d.Builtin, IntervalSeconds: d.IntervalSeconds,
	}
}

// requirePolicy answers 404 rather than panicking where filtering is not wired.
func (a *API) requirePolicy(w http.ResponseWriter) bool {
	if a.policy == nil {
		writeErr(w, http.StatusNotFound, "not_found", "", "blacklist filtering is not enabled")
		return false
	}
	return true
}

func (a *API) getBlacklistSettings(w http.ResponseWriter, _ *http.Request) {
	if !a.requirePolicy(w) {
		return
	}
	set, err := a.policy.Settings()
	if err != nil {
		writeRegistryErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": set.Enabled, "block_ttl": set.BlockTTL})
}

// patchBlacklistSettings merges onto the current settings: an omitted field
// keeps its value, matching PATCH /services/{id}.
func (a *API) patchBlacklistSettings(w http.ResponseWriter, r *http.Request) {
	if !a.requirePolicy(w) {
		return
	}
	cur, err := a.policy.Settings()
	if err != nil {
		writeRegistryErr(w, err)
		return
	}
	d := struct {
		Enabled  bool `json:"enabled"`
		BlockTTL int  `json:"block_ttl"`
	}{Enabled: cur.Enabled, BlockTTL: cur.BlockTTL}
	if !decode(w, r, &d) {
		return
	}
	if err := a.policy.SetSettings(d.Enabled, d.BlockTTL); err != nil {
		writeRegistryErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": d.Enabled, "block_ttl": d.BlockTTL})
}

func (a *API) listBlacklistLists(w http.ResponseWriter, _ *http.Request) {
	if !a.requirePolicy(w) {
		return
	}
	lists, err := a.policy.Lists()
	if err != nil {
		writeRegistryErr(w, err)
		return
	}
	out := make([]blacklistListDTO, 0, len(lists))
	for _, l := range lists {
		out = append(out, toBlacklistListDTO(l))
	}
	writeJSON(w, http.StatusOK, map[string]any{"lists": out})
}

func (a *API) createBlacklistList(w http.ResponseWriter, r *http.Request) {
	if !a.requirePolicy(w) {
		return
	}
	d := blacklistListDTO{Enabled: true}
	if !decode(w, r, &d) {
		return
	}
	d.ID = 0
	id, err := a.policy.PutList(fromBlacklistListDTO(d))
	if err != nil {
		writeRegistryErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": id})
}

// updateBlacklistList merges the body onto the current definition.
func (a *API) updateBlacklistList(w http.ResponseWriter, r *http.Request) {
	if !a.requirePolicy(w) {
		return
	}
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	lists, err := a.policy.Lists()
	if err != nil {
		writeRegistryErr(w, err)
		return
	}
	var cur *store.BlacklistList
	for i := range lists {
		if lists[i].ID == id {
			cur = &lists[i]
		}
	}
	if cur == nil {
		writeErr(w, http.StatusNotFound, "not_found", "id", "no such list")
		return
	}
	d := toBlacklistListDTO(*cur)
	if !decode(w, r, &d) {
		return
	}
	d.ID = id
	if _, err := a.policy.PutList(fromBlacklistListDTO(d)); err != nil {
		writeRegistryErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id})
}

func (a *API) deleteBlacklistList(w http.ResponseWriter, r *http.Request) {
	if !a.requirePolicy(w) {
		return
	}
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := a.policy.DeleteList(id); err != nil {
		writeRegistryErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// refreshBlacklistList downloads one list now. The id "all" refreshes every
// enabled list.
func (a *API) refreshBlacklistList(w http.ResponseWriter, r *http.Request) {
	if !a.requirePolicy(w) {
		return
	}
	var id int64
	if r.PathValue("id") != "all" {
		var ok bool
		if id, ok = pathID(w, r); !ok {
			return
		}
	}
	if err := a.policy.Refresh(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeRegistryErr(w, err)
			return
		}
		writeErr(w, http.StatusBadGateway, "refresh_failed", "", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"refreshed": r.PathValue("id")})
}

func ruleKind(w http.ResponseWriter, r *http.Request) (string, bool) {
	kind := strings.ToLower(r.PathValue("kind"))
	if kind != policy.PolicyAllow && kind != policy.PolicyDeny {
		writeErr(w, http.StatusNotFound, "not_found", "kind", "a rule is either allow or deny")
		return "", false
	}
	return kind, true
}

func (a *API) listBlacklistRules(w http.ResponseWriter, r *http.Request) {
	if !a.requirePolicy(w) {
		return
	}
	kind, ok := ruleKind(w, r)
	if !ok {
		return
	}
	rules, err := a.policy.Rules()
	if err != nil {
		writeRegistryErr(w, err)
		return
	}
	out := []blacklistRuleDTO{}
	for _, rl := range rules {
		if rl.Kind == kind {
			out = append(out, blacklistRuleDTO{ID: rl.ID, Kind: rl.Kind, Domain: rl.Domain})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": out})
}

func (a *API) createBlacklistRule(w http.ResponseWriter, r *http.Request) {
	if !a.requirePolicy(w) {
		return
	}
	kind, ok := ruleKind(w, r)
	if !ok {
		return
	}
	var d struct {
		Domain string `json:"domain"`
	}
	if !decode(w, r, &d) {
		return
	}
	id, err := a.policy.AddRule(kind, d.Domain)
	if err != nil {
		writeRegistryErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": id})
}

func (a *API) deleteBlacklistRule(w http.ResponseWriter, r *http.Request) {
	if !a.requirePolicy(w) {
		return
	}
	if _, ok := ruleKind(w, r); !ok {
		return
	}
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := a.policy.DeleteRule(id); err != nil {
		writeRegistryErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) testBlacklist(w http.ResponseWriter, r *http.Request) {
	if !a.requirePolicy(w) {
		return
	}
	name := r.URL.Query().Get("name")
	if strings.TrimSpace(name) == "" {
		writeErr(w, http.StatusBadRequest, "name_required", "name", "a name to test is required")
		return
	}
	d, err := a.policy.Test(name)
	if err != nil {
		writeRegistryErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"name": name, "blocked": d.Blocked, "policy": d.Policy})
}
