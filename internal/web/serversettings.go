package web

import (
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

	// Exactly what the operator typed in the confirmation box: anything derived
	// from the submitted allow_query would confirm the exposure on their behalf.
	confirm := strings.TrimSpace(r.PostFormValue("confirm_public"))
	if err := s.o.Settings.Set(v, confirm); err != nil {
		s.serverSettingsError(w, r, v, err)
		return
	}
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
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
