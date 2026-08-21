package web

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/yoshiofthewire/kydns-server/internal/settings"
	"github.com/yoshiofthewire/kydns-server/internal/store"
)

// RestartItem is one setting whose stored value differs from the one the
// process is running. internal/app owns the comparison and converts to this
// type, because it imports this package and cannot be imported back.
type RestartItem struct{ Key, Running, Stored string }

// lines splits a textarea into entries. Blank lines and stray whitespace are
// what a person actually types, so they are not an error.
func lines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

// intField reads one numeric input. A non-number is reported against its own
// field rather than silently becoming zero.
func intField(r *http.Request, name string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(r.PostFormValue(name)))
	if err != nil {
		return 0, settings.FieldError{Field: name, Msg: "must be a whole number"}
	}
	return n, nil
}

// liveSettings returns the running settings, or false when the service is not
// wired or has not loaded yet, which the screens render as the read-only view
// rather than as a broken form.
func (s *Server) liveSettings() (store.Settings, bool) {
	if s.o.Settings == nil {
		return store.Settings{}, false
	}
	v, err := s.o.Settings.Get()
	if err != nil {
		s.o.Logger.Error("read settings", "error", err)
		return store.Settings{}, false
	}
	return v, true
}

func (s *Server) allowTailscale() bool {
	v, ok := s.liveSettings()
	return ok && v.AllowTailscale
}

// publicRanges names the allow_query entries that reach past the LAN, in the
// masked form the ACL actually enforces.
func (s *Server) publicRanges() []string {
	v, ok := s.liveSettings()
	if !ok {
		return nil
	}
	return settings.PublicPrefixes(v.AllowQuery)
}

func (s *Server) restartPending() []RestartItem {
	if s.o.RestartPending == nil {
		return nil
	}
	return s.o.RestartPending()
}

func (s *Server) postServerSettings(w http.ResponseWriter, r *http.Request) {
	if s.o.Settings == nil {
		http.Error(w, "settings are not wired", http.StatusInternalServerError)
		return
	}
	v := store.Settings{
		PrivateDomain: strings.TrimSpace(r.PostFormValue("private_domain")),
		ReverseZones:  lines(r.PostFormValue("reverse_zones")),
		Upstreams:     lines(r.PostFormValue("upstreams")),
		AllowQuery:    lines(r.PostFormValue("allow_query")),
		DHCPLeaseFile: strings.TrimSpace(r.PostFormValue("dhcp_lease_file")),
		// An unchecked box posts nothing, so presence is the value. Reading it
		// any other way makes a toggle that can be turned on and never off.
		AllowTailscale: r.PostFormValue("allow_tailscale") != "",
		LogQueries:     r.PostFormValue("log_queries") != "",
		LogClientIP:    r.PostFormValue("log_client_ip") != "",
	}
	for _, f := range []struct {
		name string
		dst  *int
	}{
		{"ttl", &v.TTL},
		{"cache_min_ttl", &v.CacheMinTTL},
		{"cache_max_ttl", &v.CacheMaxTTL},
		{"negative_max_ttl", &v.NegativeMaxTTL},
		{"cache_entries", &v.CacheEntries},
		{"discovery_interval", &v.DiscoveryInterval},
		{"health_interval", &v.HealthInterval},
		{"health_timeout", &v.HealthTimeout},
		{"health_workers", &v.HealthWorkers},
	} {
		n, err := intField(r, f.name)
		if err != nil {
			s.serverSettingsError(w, r, v, err)
			return
		}
		*f.dst = n
	}

	// The built-in DHCP server has no field on this form yet, and this handler
	// rebuilds the whole document from what was posted: without carrying them
	// over, saving anything else here switches a running DHCP server off. If
	// the current values cannot be read, there is nothing to carry over, so the
	// save is refused rather than written with seven zeroes.
	cur, ok := s.liveSettings()
	if !ok {
		s.serverSettingsError(w, r, v,
			errors.New("the current settings could not be read, so this save was not applied; try again"))
		return
	}
	v.DHCPEnabled, v.DHCPInterface = cur.DHCPEnabled, cur.DHCPInterface
	v.DHCPRangeStart, v.DHCPRangeEnd = cur.DHCPRangeStart, cur.DHCPRangeEnd
	v.DHCPGateway, v.DHCPLeaseSeconds = cur.DHCPGateway, cur.DHCPLeaseSeconds
	v.DHCPSecondaryDNS, v.DHCPAllowForeign = cur.DHCPSecondaryDNS, cur.DHCPAllowForeign

	// Renaming the private zone moves every manual record with it. That is the
	// operator's data, so they see exactly what will change and say yes before
	// it happens — once per rename, not on every save.
	if plan := s.planZoneRename(cur.PrivateDomain, v.PrivateDomain); plan != nil &&
		r.PostFormValue("confirm_rename") != v.PrivateDomain {
		s.serverSettingsRename(w, r, v, plan)
		return
	}

	// Exactly what the operator typed in the confirmation box: anything derived
	// from the submitted allow_query would confirm the exposure on their behalf.
	confirm := strings.TrimSpace(r.PostFormValue("confirm_public"))
	if err := s.o.Settings.Set(v, confirm); err != nil {
		s.serverSettingsError(w, r, v, err)
		return
	}
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

// renameRow is one record the rename will move.
type renameRow struct{ From, To string }

// zoneRename is what changing the private domain would do to the records.
type zoneRename struct {
	From, To string
	Confirm  string // the domain exactly as typed, echoed back to authorize it
	Rows     []renameRow
	Count    int
	More     int
}

// renamePreview caps the list. A long one is a wall of text nobody reads, and
// the count above it is the number that matters.
const renamePreview = 12

// planZoneRename reports what moving from one private domain to another would
// rewrite, or nil when nothing would change: a first save, the same domain
// written differently, or a zone with no manual records in it.
func (s *Server) planZoneRename(from, to string) *zoneRename {
	fromZ, toZ := store.ZoneSuffix(from), store.ZoneSuffix(to)
	if fromZ == "" || toZ == "" || fromZ == toZ || s.o.Registry == nil {
		return nil
	}
	recs, err := s.o.Registry.Records()
	if err != nil {
		s.o.Logger.Error("read records for the rename preview", "error", err)
		return nil
	}
	plan := &zoneRename{From: fromZ, To: toZ, Confirm: to}
	for _, rec := range recs {
		name, movedName := store.RenameInZone(rec.Name, fromZ, toZ)
		value, movedValue := rec.Value, false
		if rec.Type == "CNAME" || rec.Type == "PTR" {
			value, movedValue = store.RenameInZone(rec.Value, fromZ, toZ)
		}
		if !movedName && !movedValue {
			continue
		}
		plan.Count++
		if len(plan.Rows) < renamePreview {
			row := renameRow{From: rec.Name, To: name}
			if movedValue {
				row.From += " → " + rec.Value
				row.To += " → " + value
			}
			plan.Rows = append(plan.Rows, row)
		}
	}
	if plan.Count == 0 {
		return nil
	}
	plan.More = plan.Count - len(plan.Rows)
	return plan
}

// serverSettingsRename re-renders the form with everything the operator typed
// still in it, plus what saving would rewrite. Saving again authorizes it.
func (s *Server) serverSettingsRename(w http.ResponseWriter, r *http.Request, attempted store.Settings, plan *zoneRename) {
	data := s.settingsData("", "")
	data["Server"] = attempted
	data["Rename"] = plan
	s.render(w, r, "settings.html", data)
}

// serverSettingsError re-renders with the rejected input still in the boxes.
// Discarding what the operator typed is the fastest way to lose a long
// upstream list to a typo in one field.
func (s *Server) serverSettingsError(w http.ResponseWriter, r *http.Request, attempted store.Settings, err error) {
	data := s.settingsData("", "")
	data["Server"] = attempted
	// FieldError already reads as "field: what is wrong with it", so the one
	// message both names the box and says why.
	data["ServerError"] = err.Error()
	w.WriteHeader(http.StatusBadRequest)
	s.render(w, r, "settings.html", data)
}
