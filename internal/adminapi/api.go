// Package adminapi is the JSON transport over registry. It holds no business
// rules: every validation lives in registry so the CLI and the future web UI
// cannot drift from it.
package adminapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/yoshiofthewire/kydns-server/internal/discovery/dhcp"
	"github.com/yoshiofthewire/kydns-server/internal/dnsserver"
	"github.com/yoshiofthewire/kydns-server/internal/health"
	"github.com/yoshiofthewire/kydns-server/internal/policy"
	"github.com/yoshiofthewire/kydns-server/internal/registry"
	"github.com/yoshiofthewire/kydns-server/internal/settings"
	"github.com/yoshiofthewire/kydns-server/internal/store"
)

type API struct {
	reg             *registry.Registry
	acl             *dnsserver.ACL
	cache           *dnsserver.Cache
	leases          func() []dhcp.Lease
	discoveryOn     func() bool
	health          func() []health.Status
	policy          *policy.Service
	settings        *settings.Service
	metrics         *dnsserver.Metrics
	replicaStatus   func() ReplicaStatus
	replicaAdmin    ReplicaAdmin
	replicaJoiner   ReplicaJoiner
	replicaPromoter ReplicaPromoter
}

// ReplicaStatus is what GET /api/v1/replica/status renders. It mirrors
// app.ReplicaStatus field-for-field: adminapi cannot import internal/app,
// because app already imports adminapi to wire this endpoint.
type ReplicaStatus struct {
	Role          string `json:"role"`
	PrimaryAddr   string `json:"primary_address,omitempty"`
	PrimaryNodeID string `json:"primary_node_id,omitempty"`
	NodeID        string `json:"node_id,omitempty"`
	LastSyncUnix  int64  `json:"last_sync_unix,omitempty"`
	LastVersion   int64  `json:"last_version,omitempty"`
	LastError     string `json:"last_error,omitempty"`
	Stale         bool   `json:"stale,omitempty"`
}

// topBlockedShown is how many blocked names /api/v1/stats lists.
const topBlockedShown = 10

// WithMetrics attaches the query counters. It is optional, so the API still
// constructs where the DNS side is not running.
func (a *API) WithMetrics(m *dnsserver.Metrics) *API {
	a.metrics = m
	return a
}

func NewAPI(reg *registry.Registry, acl *dnsserver.ACL, cache *dnsserver.Cache) *API {
	return &API{reg: reg, acl: acl, cache: cache}
}

// WithProviders attaches discovery and health data. All three are optional, so
// the API still constructs where neither subsystem is running. discoveryOn is
// separate from leases because a lease source can be turned on and off at
// runtime: an empty lease set is not the same answer as "not enabled", and only
// discoveryOn is asked again on every request.
func (a *API) WithProviders(leases func() []dhcp.Lease, statuses func() []health.Status, discoveryOn func() bool) *API {
	a.leases, a.health, a.discoveryOn = leases, statuses, discoveryOn
	return a
}

// discoveryEnabled reports whether a lease source is configured right now. A
// nil provider means discovery was never wired, which is off.
func (a *API) discoveryEnabled() bool {
	return a.discoveryOn != nil && a.discoveryOn()
}

func (a *API) leaseList() []dhcp.Lease {
	if a.leases == nil {
		return nil
	}
	return a.leases()
}

// WithPolicy attaches the blacklist service. It is optional, so the API still
// constructs where filtering is not running.
func (a *API) WithPolicy(p *policy.Service) *API {
	a.policy = p
	return a
}

// WithSettings attaches the settings service. It is optional, so the API
// still constructs where settings are not wired.
func (a *API) WithSettings(s *settings.Service) *API {
	a.settings = s
	return a
}

// WithReplication attaches the status producer for GET /api/v1/replica/status.
// It is optional; an API built without it reports standalone, since that is
// what a node with no replication configured actually is.
func (a *API) WithReplication(status func() ReplicaStatus) *API {
	a.replicaStatus = status
	return a
}

type addressDTO struct {
	Address string `json:"address" yaml:"address"`
	View    string `json:"view,omitempty" yaml:"view,omitempty"`
}

type serviceDTO struct {
	ID            int64        `json:"id,omitempty" yaml:"-"`
	Name          string       `json:"name" yaml:"name"`
	Addresses     []addressDTO `json:"addresses" yaml:"addresses"`
	Aliases       []string     `json:"aliases,omitempty" yaml:"aliases,omitempty"`
	CheckURL      string       `json:"check_url,omitempty" yaml:"check_url,omitempty"`
	CheckInsecure bool         `json:"check_insecure,omitempty" yaml:"check_insecure,omitempty"`
	ProxyAddress  string       `json:"proxy_address,omitempty" yaml:"proxy_address,omitempty"`
	RouteViaProxy bool         `json:"route_via_proxy,omitempty" yaml:"route_via_proxy,omitempty"`
}

type recordDTO struct {
	ID    int64  `json:"id,omitempty" yaml:"-"`
	Name  string `json:"name" yaml:"name"`
	Type  string `json:"type" yaml:"type"`
	Value string `json:"value" yaml:"value"`
	View  string `json:"view,omitempty" yaml:"view,omitempty"`
}

type viewDTO struct {
	Name    string   `json:"name" yaml:"name"`
	Subnets []string `json:"subnets" yaml:"subnets"`
}

// blacklistDoc is the exportable slice of filtering policy: settings, list
// definitions and one-off rules. Downloaded bodies and cache validators are
// runtime state and have no field here to live in.
type blacklistDoc struct {
	Enabled  bool               `json:"enabled" yaml:"enabled"`
	BlockTTL int                `json:"block_ttl" yaml:"block_ttl"`
	Lists    []blacklistListDTO `json:"lists" yaml:"lists"`
	Rules    []blacklistRuleDTO `json:"rules" yaml:"rules"`
}

// transfer is the export/import document. It carries no secrets by
// construction: there is nowhere in this struct to put one.
type transfer struct {
	Views     []viewDTO     `json:"views" yaml:"views"`
	Services  []serviceDTO  `json:"services" yaml:"services"`
	Records   []recordDTO   `json:"records" yaml:"records"`
	Blacklist *blacklistDoc `json:"blacklist,omitempty" yaml:"blacklist,omitempty"`
	Settings  *settingsDTO  `json:"settings,omitempty" yaml:"settings,omitempty"`
}

func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	a.Routes(mux)
	return a.WriteGate(mux)
}

// The three writes a replica must still accept. Promote is the operator's
// deliberate escape from being a replica; the two pairing calls are how a
// node becomes one. Everything else a replica accepts would be silently
// overwritten by the primary on the next pull.
const (
	PathReplicaPairPeek = "/api/v1/replica/pair/peek"
	PathReplicaJoin     = "/api/v1/replica/join"
	PathReplicaPromote  = "/api/v1/replica/promote"
)

// writeExempt is the whole exemption list, shared with route registration so
// renaming a route cannot silently un-exempt it.
var writeExempt = map[string]bool{
	PathReplicaPairPeek: true,
	PathReplicaJoin:     true,
	PathReplicaPromote:  true,
}

// authenticated is the one bearer-token check, shared so the write gate and
// the handlers behind it can never disagree about who is anonymous.
func (a *API) authenticated(r *http.Request) bool {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	return token != "" && a.reg != nil && a.reg.AuthenticateToken(token)
}

// registrar is the sliver of *http.ServeMux that registration uses. ServeMux
// cannot be enumerated, so this is what lets a test derive the route table
// from the router rather than hand-listing it.
type registrar interface {
	HandleFunc(pattern string, h func(http.ResponseWriter, *http.Request))
}

// Routes registers the API on a mux, so the web transport can share one
// listener with it. The mux is not where writes are refused: wrap the whole
// server handler in WriteGate.
func (a *API) Routes(mux *http.ServeMux) { a.routes(mux) }

func (a *API) routes(mux registrar) {
	mux.HandleFunc("GET /api/v1/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})

	auth := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if !a.authenticated(r) {
				writeErr(w, http.StatusUnauthorized, "unauthenticated", "", "a valid bearer token is required")
				return
			}
			h(w, r)
		}
	}

	mux.HandleFunc("GET /api/v1/services", auth(a.listServices))
	mux.HandleFunc("POST /api/v1/services", auth(a.createService))
	mux.HandleFunc("GET /api/v1/services/{id}", auth(a.getService))
	mux.HandleFunc("PATCH /api/v1/services/{id}", auth(a.updateService))
	mux.HandleFunc("DELETE /api/v1/services/{id}", auth(a.deleteService))
	mux.HandleFunc("GET /api/v1/records", auth(a.listRecords))
	mux.HandleFunc("POST /api/v1/records", auth(a.createRecord))
	mux.HandleFunc("DELETE /api/v1/records/{id}", auth(a.deleteRecord))
	mux.HandleFunc("GET /api/v1/views", auth(a.listViews))
	mux.HandleFunc("POST /api/v1/views", auth(a.createView))
	mux.HandleFunc("DELETE /api/v1/views/{name}", auth(a.deleteView))
	mux.HandleFunc("GET /api/v1/tokens", auth(a.listTokens))
	mux.HandleFunc("POST /api/v1/tokens", auth(a.createToken))
	mux.HandleFunc("DELETE /api/v1/tokens/{id}", auth(a.deleteToken))
	mux.HandleFunc("GET /api/v1/export", auth(a.export))
	mux.HandleFunc("POST /api/v1/import", auth(a.importDoc))
	mux.HandleFunc("GET /api/v1/leases", auth(a.listLeases))
	mux.HandleFunc("POST /api/v1/leases/{ip}/promote", auth(a.promoteLease))
	mux.HandleFunc("GET /api/v1/health", auth(a.listHealth))
	mux.HandleFunc("GET /api/v1/stats", auth(a.stats))
	mux.HandleFunc("POST /api/v1/cache/flush", auth(a.flushCache))

	mux.HandleFunc("GET /api/v1/blacklists/settings", auth(a.getBlacklistSettings))
	mux.HandleFunc("PATCH /api/v1/blacklists/settings", auth(a.patchBlacklistSettings))
	mux.HandleFunc("GET /api/v1/blacklists/lists", auth(a.listBlacklistLists))
	mux.HandleFunc("POST /api/v1/blacklists/lists", auth(a.createBlacklistList))
	mux.HandleFunc("PATCH /api/v1/blacklists/lists/{id}", auth(a.updateBlacklistList))
	mux.HandleFunc("DELETE /api/v1/blacklists/lists/{id}", auth(a.deleteBlacklistList))
	mux.HandleFunc("POST /api/v1/blacklists/lists/{id}/refresh", auth(a.refreshBlacklistList))
	mux.HandleFunc("GET /api/v1/blacklists/rules/{kind}", auth(a.listBlacklistRules))
	mux.HandleFunc("POST /api/v1/blacklists/rules/{kind}", auth(a.createBlacklistRule))
	mux.HandleFunc("DELETE /api/v1/blacklists/rules/{kind}/{id}", auth(a.deleteBlacklistRule))
	mux.HandleFunc("GET /api/v1/blacklists/test", auth(a.testBlacklist))

	mux.HandleFunc("GET /api/v1/settings", auth(a.getSettings))
	mux.HandleFunc("PATCH /api/v1/settings", auth(a.patchSettings))

	mux.HandleFunc("GET /api/v1/replica/status", auth(a.getReplicaStatus))

	// Registered from the constants the exemption list is built from, so a
	// renamed path cannot end up gated on one side and exempt on the other.
	mux.HandleFunc("POST "+PathReplicaPairPeek, auth(a.peekPrimary))
	mux.HandleFunc("POST "+PathReplicaJoin, auth(a.joinPrimary))
	mux.HandleFunc("POST "+PathReplicaPromote, auth(a.promoteThisNode))

	// Managing replicas is the primary's job. These two are deliberately not in
	// writeExempt: a replica minting invites would enroll nodes its primary
	// knows nothing about, and unpairing there would be undone on the next pull.
	mux.HandleFunc("POST /api/v1/replicas/invite", auth(a.inviteReplica))
	mux.HandleFunc("GET /api/v1/replicas", auth(a.listReplicas))
	mux.HandleFunc("DELETE /api/v1/replicas/{node_id}", auth(a.removeReplica))
}

// roleReplica mirrors app.Role's replica value, which adminapi cannot import
// because app already imports adminapi.
const roleReplica = "replica"

// PathPrefix is the surface WriteGate covers. The web transport's own writes
// are gated separately: a browser gets a page, not a JSON error, so its gate
// reads this to leave the API alone.
const PathPrefix = "/api/v1/"

// WriteGate refuses writes on a replica. A write that lands here is not just
// unauthorized, it is discarded: the primary overwrites this node's config on
// the next pull, and the operator would never know. It wraps the whole server
// handler rather than routes, so a path with no route, or a route registered
// somewhere else entirely, is refused too.
func (a *API) WriteGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, PathPrefix) ||
			r.Method == http.MethodGet || r.Method == http.MethodHead ||
			writeExempt[r.URL.Path] || a.replicaStatus == nil {
			next.ServeHTTP(w, r)
			return
		}
		// Read per request, so promotion stops the refusals immediately.
		st := a.replicaStatus()
		// An anonymous caller gets the 401 it always got: this gate sits
		// outside auth and must not tell a stranger where the primary is.
		if st.Role != roleReplica || !a.authenticated(r) {
			next.ServeHTTP(w, r)
			return
		}
		where := st.PrimaryAddr
		if where == "" {
			where = "its primary"
		}
		writeErr(w, http.StatusConflict, "read_only_replica", "",
			"this node is a read-only replica; make this change on "+where)
	})
}

func (a *API) getReplicaStatus(w http.ResponseWriter, _ *http.Request) {
	if a.replicaStatus == nil {
		writeJSON(w, http.StatusOK, ReplicaStatus{Role: "standalone"})
		return
	}
	writeJSON(w, http.StatusOK, a.replicaStatus())
}

type errBody struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		Field   string `json:"field,omitempty"`
	} `json:"error"`
}

func writeErr(w http.ResponseWriter, status int, code, field, msg string) {
	var b errBody
	b.Error.Code, b.Error.Field, b.Error.Message = code, field, msg
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(b)
}

// writeRegistryErr maps domain errors onto status codes in one place so every
// endpoint answers consistently.
func writeRegistryErr(w http.ResponseWriter, err error) {
	var ve *registry.ValidationError
	switch {
	case errors.As(err, &ve):
		writeErr(w, http.StatusBadRequest, ve.Code, ve.Field, ve.Message)
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusNotFound, "not_found", "", err.Error())
	case errors.Is(err, store.ErrViewInUse):
		writeErr(w, http.StatusConflict, "view_in_use", "name", err.Error())
	case errors.Is(err, store.ErrDuplicateName), errors.Is(err, store.ErrDuplicateCIDR):
		writeErr(w, http.StatusConflict, "conflict", "name", err.Error())
	default:
		writeErr(w, http.StatusInternalServerError, "internal", "", err.Error())
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	body, ok := bodyBytes(w, r)
	if !ok {
		return false
	}
	if err := json.Unmarshal(body, v); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed_json", "", err.Error())
		return false
	}
	return true
}

// maxBody bounds request bodies read in full, so an authenticated client
// can't hold a handler open by trickling bytes forever.
const maxBody = 16 << 20

// bodyBytes reads the whole request body up front so a handler can inspect it
// (e.g. which keys are present) before unmarshalling it.
func bodyBytes(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "malformed_json", "", err.Error())
		return nil, false
	}
	return body, true
}

func pathID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "id_invalid", "id", "id must be an integer")
		return 0, false
	}
	return id, true
}

func toServiceDTO(s store.Service) serviceDTO {
	d := serviceDTO{
		ID: s.ID, Name: s.Name, Aliases: s.Aliases, CheckURL: s.CheckURL, CheckInsecure: s.CheckInsecure,
		ProxyAddress: s.ProxyAddress, RouteViaProxy: s.RouteViaProxy,
	}
	for _, a := range s.Addresses {
		d.Addresses = append(d.Addresses, addressDTO{Address: a.Address, View: a.View})
	}
	return d
}

func fromServiceDTO(d serviceDTO) store.Service {
	s := store.Service{
		ID: d.ID, Name: d.Name, Aliases: d.Aliases, CheckURL: d.CheckURL, CheckInsecure: d.CheckInsecure,
		ProxyAddress: d.ProxyAddress, RouteViaProxy: d.RouteViaProxy,
	}
	for _, a := range d.Addresses {
		s.Addresses = append(s.Addresses, store.Address{Address: a.Address, View: a.View})
	}
	return s
}

func (a *API) listServices(w http.ResponseWriter, _ *http.Request) {
	svcs, err := a.reg.Services()
	if err != nil {
		writeRegistryErr(w, err)
		return
	}
	out := make([]serviceDTO, 0, len(svcs))
	for _, s := range svcs {
		out = append(out, toServiceDTO(s))
	}
	writeJSON(w, http.StatusOK, map[string]any{"services": out})
}

func (a *API) createService(w http.ResponseWriter, r *http.Request) {
	var d serviceDTO
	if !decode(w, r, &d) {
		return
	}
	id, err := a.reg.PutService(fromServiceDTO(d))
	if err != nil {
		writeRegistryErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": id})
}

func (a *API) getService(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	svc, err := a.reg.Service(id)
	if err != nil {
		writeRegistryErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toServiceDTO(svc))
}

// updateService merges the body onto the current service: an omitted field
// keeps its value. A provided addresses or aliases array replaces the whole
// slice rather than merging element-by-element (which is how a tailnet
// address gets added without leaking the old address's view onto it).
func (a *API) updateService(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	cur, err := a.reg.Service(id)
	if err != nil {
		writeRegistryErr(w, err)
		return
	}
	body, ok := bodyBytes(w, r)
	if !ok {
		return
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed_json", "", err.Error())
		return
	}
	// encoding/json matches struct fields case-insensitively, so presence
	// must be checked the same way or a body like {"Addresses":...} would
	// skip the reset below and merge into the old slice element-by-element.
	present := make(map[string]bool, len(raw))
	for k := range raw {
		present[strings.ToLower(k)] = true
	}
	d := toServiceDTO(cur)
	if present["addresses"] {
		d.Addresses = nil
	}
	if err := json.Unmarshal(body, &d); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed_json", "", err.Error())
		return
	}
	svc := fromServiceDTO(d)
	svc.ID = id
	if _, err := a.reg.PutService(svc); err != nil {
		writeRegistryErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id})
}

func (a *API) deleteService(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := a.reg.DeleteService(id); err != nil {
		writeRegistryErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) listRecords(w http.ResponseWriter, _ *http.Request) {
	recs, err := a.reg.Records()
	if err != nil {
		writeRegistryErr(w, err)
		return
	}
	out := make([]recordDTO, 0, len(recs))
	for _, r := range recs {
		out = append(out, recordDTO{ID: r.ID, Name: r.Name, Type: r.Type, Value: r.Value, View: r.View})
	}
	writeJSON(w, http.StatusOK, map[string]any{"records": out})
}

func (a *API) createRecord(w http.ResponseWriter, r *http.Request) {
	var d recordDTO
	if !decode(w, r, &d) {
		return
	}
	id, err := a.reg.PutRecord(store.Record{Name: d.Name, Type: d.Type, Value: d.Value, View: d.View})
	if err != nil {
		writeRegistryErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": id})
}

func (a *API) deleteRecord(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := a.reg.DeleteRecord(id); err != nil {
		writeRegistryErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) listViews(w http.ResponseWriter, _ *http.Request) {
	views, err := a.reg.Views()
	if err != nil {
		writeRegistryErr(w, err)
		return
	}
	out := make([]viewDTO, 0, len(views))
	for _, v := range views {
		out = append(out, viewDTO{Name: v.Name, Subnets: v.Subnets})
	}
	writeJSON(w, http.StatusOK, map[string]any{"views": out})
}

func (a *API) createView(w http.ResponseWriter, r *http.Request) {
	var d viewDTO
	if !decode(w, r, &d) {
		return
	}
	if err := a.reg.PutView(store.View{Name: d.Name, Subnets: d.Subnets}); err != nil {
		writeRegistryErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"name": d.Name})
}

func (a *API) deleteView(w http.ResponseWriter, r *http.Request) {
	if err := a.reg.DeleteView(r.PathValue("name")); err != nil {
		writeRegistryErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) listTokens(w http.ResponseWriter, _ *http.Request) {
	toks, err := a.reg.Tokens()
	if err != nil {
		writeRegistryErr(w, err)
		return
	}
	// Never the hash, never the plaintext: label and metadata only.
	out := make([]map[string]any, 0, len(toks))
	for _, t := range toks {
		out = append(out, map[string]any{
			"id": t.ID, "label": t.Label,
			"created_at": t.CreatedAt, "last_used_at": t.LastUsedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": out})
}

func (a *API) createToken(w http.ResponseWriter, r *http.Request) {
	var d struct {
		Label string `json:"label"`
	}
	if !decode(w, r, &d) {
		return
	}
	plaintext, err := a.reg.CreateToken(d.Label)
	if err != nil {
		writeRegistryErr(w, err)
		return
	}
	// The only time the plaintext is ever returned.
	writeJSON(w, http.StatusCreated, map[string]any{"token": plaintext, "label": d.Label})
}

func (a *API) deleteToken(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := a.reg.DeleteToken(id); err != nil {
		writeRegistryErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) snapshotDoc() (transfer, error) {
	doc := transfer{Views: []viewDTO{}, Services: []serviceDTO{}, Records: []recordDTO{}}
	views, err := a.reg.Views()
	if err != nil {
		return doc, err
	}
	for _, v := range views {
		doc.Views = append(doc.Views, viewDTO{Name: v.Name, Subnets: v.Subnets})
	}
	svcs, err := a.reg.Services()
	if err != nil {
		return doc, err
	}
	for _, s := range svcs {
		d := toServiceDTO(s)
		d.ID = 0
		doc.Services = append(doc.Services, d)
	}
	recs, err := a.reg.Records()
	if err != nil {
		return doc, err
	}
	for _, r := range recs {
		doc.Records = append(doc.Records, recordDTO{Name: r.Name, Type: r.Type, Value: r.Value, View: r.View})
	}
	if a.policy != nil {
		set, err := a.policy.Settings()
		if err != nil {
			return doc, err
		}
		bl := &blacklistDoc{
			Enabled: set.Enabled, BlockTTL: set.BlockTTL,
			Lists: []blacklistListDTO{}, Rules: []blacklistRuleDTO{},
		}
		lists, err := a.policy.Lists()
		if err != nil {
			return doc, err
		}
		for _, l := range lists {
			// Definition only: the yaml tags drop every runtime field, and the
			// zero values keep them out of the JSON form too.
			bl.Lists = append(bl.Lists, blacklistListDTO{
				Name: l.Name, URL: l.URL, Format: l.Format, Description: l.Description,
				Enabled: l.Enabled, Builtin: l.Builtin, IntervalSeconds: l.IntervalSeconds,
			})
		}
		rules, err := a.policy.Rules()
		if err != nil {
			return doc, err
		}
		for _, r := range rules {
			bl.Rules = append(bl.Rules, blacklistRuleDTO{Kind: r.Kind, Domain: r.Domain})
		}
		doc.Blacklist = bl
	}
	if a.settings != nil {
		cur, err := a.settings.Get()
		if err != nil {
			return doc, err
		}
		d := toSettingsDTO(cur)
		doc.Settings = &d
	}
	return doc, nil
}

// WriteExport writes the export document in the requested format. The web
// transport reuses this so the two can never diverge on what a backup holds.
func (a *API) WriteExport(w http.ResponseWriter, format string) error {
	doc, err := a.snapshotDoc()
	if err != nil {
		return err
	}
	if format == "json" {
		w.Header().Set("Content-Type", "application/json")
		return json.NewEncoder(w).Encode(doc)
	}
	w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
	return yaml.NewEncoder(w).Encode(doc)
}

func (a *API) export(w http.ResponseWriter, r *http.Request) {
	if err := a.WriteExport(w, r.URL.Query().Get("format")); err != nil {
		writeErr(w, http.StatusInternalServerError, "encode", "", err.Error())
	}
}

func (a *API) importDoc(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "read_failed", "", err.Error())
		return
	}
	var doc transfer
	// YAML is a superset of JSON, so one decoder handles both formats.
	if err := yaml.Unmarshal(body, &doc); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed_document", "", err.Error())
		return
	}

	// Check the settings block before touching the registry in either mode: a
	// document that cannot be applied must be rejected with the registry
	// untouched, not discovered after rows are already written or gone. This
	// only checks; nothing is written or applied until applySettingsDoc below.
	if doc.Settings != nil && a.settings != nil {
		if err := a.settings.CheckWrite(fromSettingsDTO(*doc.Settings), ""); err != nil {
			writeSettingsErr(w, err)
			return
		}
	}

	if r.URL.Query().Get("mode") == "replace" {
		views := make([]store.View, 0, len(doc.Views))
		for _, v := range doc.Views {
			views = append(views, store.View{Name: v.Name, Subnets: v.Subnets})
		}
		svcs := make([]store.Service, 0, len(doc.Services))
		for _, s := range doc.Services {
			svcs = append(svcs, fromServiceDTO(s))
		}
		recs := make([]store.Record, 0, len(doc.Records))
		for _, rec := range doc.Records {
			recs = append(recs, store.Record{Name: rec.Name, Type: rec.Type, Value: rec.Value, View: rec.View})
		}
		if err := a.reg.ReplaceAll(views, svcs, recs); err != nil {
			writeRegistryErr(w, err)
			return
		}
		if err := a.applyBlacklistDoc(doc.Blacklist, true); err != nil {
			writeRegistryErr(w, err)
			return
		}
		if err := a.applySettingsDoc(doc.Settings); err != nil {
			writeSettingsErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"mode": "replace"})
		return
	}

	for _, v := range doc.Views {
		if err := a.reg.PutView(store.View{Name: v.Name, Subnets: v.Subnets}); err != nil {
			writeRegistryErr(w, err)
			return
		}
	}
	for _, s := range doc.Services {
		if _, err := a.reg.PutService(fromServiceDTO(s)); err != nil {
			writeRegistryErr(w, err)
			return
		}
	}
	for _, rec := range doc.Records {
		if _, err := a.reg.PutRecord(store.Record{Name: rec.Name, Type: rec.Type, Value: rec.Value, View: rec.View}); err != nil {
			writeRegistryErr(w, err)
			return
		}
	}
	if err := a.applyBlacklistDoc(doc.Blacklist, false); err != nil {
		writeRegistryErr(w, err)
		return
	}
	if err := a.applySettingsDoc(doc.Settings); err != nil {
		writeSettingsErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"mode": "merge"})
}

// applySettingsDoc writes imported settings through the single write path. A
// document with no settings block changes nothing, so an older backup imports
// cleanly. The confirmation is always empty: only a public allow_query prefix
// already running is honoured, so restoring an export that carries one the
// server does not currently serve fails and must be confirmed by hand, the
// same guardrail a live edit goes through.
func (a *API) applySettingsDoc(doc *settingsDTO) error {
	if doc == nil || a.settings == nil {
		return nil
	}
	return a.settings.Set(fromSettingsDTO(*doc), "")
}

func (a *API) listLeases(w http.ResponseWriter, _ *http.Request) {
	out := []map[string]any{}
	for _, l := range a.leaseList() {
		out = append(out, map[string]any{
			"hostname": l.Hostname, "address": l.IP, "mac": l.MAC,
			"expires": l.Expires.Unix(),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"leases": out})
}

// promoteLease makes a discovered name durable. Leases are never persisted, so
// this is the only path from discovery into the database.
func (a *API) promoteLease(w http.ResponseWriter, r *http.Request) {
	ip := r.PathValue("ip")
	if !a.discoveryEnabled() {
		writeErr(w, http.StatusNotFound, "not_found", "ip", "lease discovery is not enabled")
		return
	}
	for _, l := range a.leaseList() {
		if l.IP != ip {
			continue
		}
		id, err := a.reg.PutService(store.Service{
			Name: l.Hostname, Addresses: []store.Address{{Address: l.IP}},
		})
		if err != nil {
			writeRegistryErr(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"id": id, "name": l.Hostname})
		return
	}
	writeErr(w, http.StatusNotFound, "not_found", "ip", "no current lease for "+ip)
}

func (a *API) listHealth(w http.ResponseWriter, _ *http.Request) {
	out := []map[string]any{}
	if a.health != nil {
		for _, s := range a.health() {
			// Zero means "not since anything": a replica renders its primary's
			// verdict, which carries no local transition time, and the epoch of a
			// zero time reads as a date in the year 1.
			since := int64(0)
			if !s.Since.IsZero() {
				since = s.Since.Unix()
			}
			out = append(out, map[string]any{
				"service_id": s.ServiceID, "name": s.Name, "state": s.State,
				"since": since, "last_error": s.LastError,
			})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"health": out})
}

func (a *API) stats(w http.ResponseWriter, _ *http.Request) {
	out := map[string]any{}
	if a.metrics != nil {
		m := a.metrics.Snapshot()
		out["queries"] = map[string]any{
			"total": m.Total, "authoritative": m.Authoritative, "forwarded": m.Forwarded,
			"blocked": m.Blocked, "refused": m.Refused, "errors": m.Errors,
			"noerror": m.NoError, "nxdomain": m.NXDomain, "servfail": m.ServFail,
			"avg_ms": m.AvgMS(), "last_query": m.LastQuery,
		}
		out["uptime_seconds"] = m.UptimeSeconds
		out["history"] = m.History
	}
	if a.acl != nil {
		s := a.acl.Stats()
		out["refusals"] = map[string]any{
			"total": s.Total, "cgnat": s.CGNAT, "last_cgnat": s.LastCGNAT,
		}
	}
	if a.cache != nil {
		c := map[string]any{"entries": a.cache.Len()}
		if a.metrics != nil {
			m := a.metrics.Snapshot()
			c["hits"], c["misses"], c["hit_rate"] = m.CacheHits, m.CacheMisses, m.CacheHitRate()
		}
		out["cache"] = c
	}
	if a.policy != nil {
		total, byList := a.policy.Counters()
		out["blocked"] = map[string]any{
			"total": total, "by_list": byList, "top": a.policy.TopBlocked(topBlockedShown),
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) flushCache(w http.ResponseWriter, _ *http.Request) {
	if a.cache != nil {
		a.cache.Flush()
	}
	w.WriteHeader(http.StatusNoContent)
}
