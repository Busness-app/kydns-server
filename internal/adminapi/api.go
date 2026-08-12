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
	"github.com/yoshiofthewire/kydns-server/internal/registry"
	"github.com/yoshiofthewire/kydns-server/internal/store"
)

type API struct {
	reg    *registry.Registry
	acl    *dnsserver.ACL
	cache  *dnsserver.Cache
	leases func() []dhcp.Lease
	health func() []health.Status
}

func NewAPI(reg *registry.Registry, acl *dnsserver.ACL, cache *dnsserver.Cache) *API {
	return &API{reg: reg, acl: acl, cache: cache}
}

// WithProviders attaches discovery and health data. Both are optional, so the
// API still constructs where neither subsystem is running.
func (a *API) WithProviders(leases func() []dhcp.Lease, statuses func() []health.Status) *API {
	a.leases, a.health = leases, statuses
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

// transfer is the export/import document. It carries no secrets by
// construction: there is nowhere in this struct to put one.
type transfer struct {
	Views    []viewDTO    `json:"views" yaml:"views"`
	Services []serviceDTO `json:"services" yaml:"services"`
	Records  []recordDTO  `json:"records" yaml:"records"`
}

func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	a.Routes(mux)
	return mux
}

// Routes registers the API on a mux, so the web transport can share one
// listener with it.
func (a *API) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})

	auth := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if token == "" || !a.reg.AuthenticateToken(token) {
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
	writeJSON(w, http.StatusOK, map[string]any{"mode": "merge"})
}

func (a *API) listLeases(w http.ResponseWriter, _ *http.Request) {
	out := []map[string]any{}
	if a.leases != nil {
		for _, l := range a.leases() {
			out = append(out, map[string]any{
				"hostname": l.Hostname, "address": l.IP, "mac": l.MAC,
				"expires": l.Expires.Unix(),
			})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"leases": out})
}

// promoteLease makes a discovered name durable. Leases are never persisted, so
// this is the only path from discovery into the database.
func (a *API) promoteLease(w http.ResponseWriter, r *http.Request) {
	ip := r.PathValue("ip")
	if a.leases == nil {
		writeErr(w, http.StatusNotFound, "not_found", "ip", "lease discovery is not enabled")
		return
	}
	for _, l := range a.leases() {
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
			out = append(out, map[string]any{
				"service_id": s.ServiceID, "name": s.Name, "state": s.State,
				"since": s.Since.Unix(), "last_error": s.LastError,
			})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"health": out})
}

func (a *API) stats(w http.ResponseWriter, _ *http.Request) {
	out := map[string]any{}
	if a.acl != nil {
		s := a.acl.Stats()
		out["refusals"] = map[string]any{
			"total": s.Total, "cgnat": s.CGNAT, "last_cgnat": s.LastCGNAT,
		}
	}
	if a.cache != nil {
		out["cache"] = map[string]any{"entries": a.cache.Len()}
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) flushCache(w http.ResponseWriter, _ *http.Request) {
	if a.cache != nil {
		a.cache.Flush()
	}
	w.WriteHeader(http.StatusNoContent)
}
