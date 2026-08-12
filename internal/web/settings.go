package web

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/yoshiofthewire/kydns-server/internal/store"
)

// restartNote is shown wherever a config value is displayed, because the
// config file is read once at startup.
const restartNote = "These come from the config file and are read at startup. " +
	"Editing them requires restarting KyDNS."

type viewRow struct {
	Name        string
	Subnets     string
	Unreachable bool
	References  int
}

// configRow is one line of the read-only config display.
type configRow struct {
	Key   string
	Value string
}

func joinOr(list []string, empty string) string {
	if len(list) == 0 {
		return empty
	}
	return strings.Join(list, ", ")
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

func secs(n int) string { return strconv.Itoa(n) + "s" }

// configRows renders the loaded config for display. Config holds no secrets
// today; if a credentialed upstream is ever added, it must be excluded here
// rather than relying on this list happening to omit it.
func (s *Server) configRows() []configRow {
	c := s.o.Config
	if c == nil {
		return nil
	}
	discovery := c.Discovery.DHCPLeaseFile
	if discovery == "" {
		discovery = "off"
	}
	return []configRow{
		{"data_dir", c.DataDir},
		{"dns.listen", c.DNS.Listen},
		{"dns.private_domain", c.DNS.PrivateDomain},
		{"dns.reverse_zones", joinOr(c.DNS.ReverseZones, "none")},
		{"dns.upstreams", joinOr(c.DNS.Upstreams, "none")},
		{"dns.allow_query", joinOr(c.DNS.AllowQuery, "none")},
		{"dns.allow_tailscale", onOff(c.DNS.AllowTailscale)},
		{"dns.ttl", secs(c.DNS.TTL)},
		{"dns.cache_min_ttl", secs(c.DNS.CacheMinTTL)},
		{"dns.cache_max_ttl", secs(c.DNS.CacheMaxTTL)},
		{"dns.negative_max_ttl", secs(c.DNS.NegativeMaxTTL)},
		{"dns.cache_entries", strconv.Itoa(c.DNS.CacheEntries)},
		{"dns.log_queries", onOff(c.DNS.LogQueries)},
		{"dns.log_client_ip", onOff(c.DNS.LogClientIP)},
		{"admin.listen", c.Admin.Listen},
		{"discovery.dhcp_lease_file", discovery},
		{"discovery.interval", secs(c.Discovery.Interval)},
		{"health.interval", secs(c.Health.Interval)},
		{"health.timeout", secs(c.Health.Timeout)},
		{"health.workers", strconv.Itoa(c.Health.Workers)},
	}
}

func (s *Server) settingsData(errMsg, newToken string) map[string]any {
	views, err := s.o.Registry.Views()
	if err != nil && errMsg == "" {
		errMsg = err.Error()
	}
	svcs, _ := s.o.Registry.Services()
	recs, _ := s.o.Registry.Records()

	// Banner condition 2, shown per row where the operator is already standing.
	unreachable := map[string]bool{}
	for _, n := range unreachableViews(views, s.o.AllowTailscale) {
		unreachable[n] = true
	}

	rows := make([]viewRow, 0, len(views))
	for _, v := range views {
		row := viewRow{
			Name:        v.Name,
			Subnets:     strings.Join(v.Subnets, ", "),
			Unreachable: unreachable[v.Name],
		}
		for _, svc := range svcs {
			for _, a := range svc.Addresses {
				if a.View == v.Name {
					row.References++
				}
			}
		}
		for _, r := range recs {
			if r.View == v.Name {
				row.References++
			}
		}
		rows = append(rows, row)
	}

	toks, _ := s.o.Registry.Tokens()
	return map[string]any{
		"Title": "Settings", "Nav": "settings",
		"Views": rows, "Tokens": toks, "NewToken": newToken,
		"Config": s.configRows(), "RestartNote": restartNote, "Error": errMsg,
	}
}

func (s *Server) getSettings(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "settings.html", s.settingsData("", ""))
}

func (s *Server) settingsError(w http.ResponseWriter, r *http.Request, err error) {
	w.WriteHeader(http.StatusBadRequest)
	s.render(w, r, "settings.html", s.settingsData(err.Error(), ""))
}

func (s *Server) postViewNew(w http.ResponseWriter, r *http.Request) {
	var subnets []string
	for _, c := range strings.Split(r.PostFormValue("subnets"), ",") {
		if c = strings.TrimSpace(c); c != "" {
			subnets = append(subnets, c)
		}
	}
	if err := s.o.Registry.PutView(store.View{Name: r.PostFormValue("name"), Subnets: subnets}); err != nil {
		s.settingsError(w, r, err)
		return
	}
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

func (s *Server) postViewDelete(w http.ResponseWriter, r *http.Request) {
	if err := s.o.Registry.DeleteView(r.PostFormValue("name")); err != nil {
		s.settingsError(w, r, err)
		return
	}
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

// postTokenNew renders the settings page directly rather than redirecting,
// because the plaintext exists only in this response.
func (s *Server) postTokenNew(w http.ResponseWriter, r *http.Request) {
	plaintext, err := s.o.Registry.CreateToken(r.PostFormValue("label"))
	if err != nil {
		s.settingsError(w, r, err)
		return
	}
	s.render(w, r, "settings.html", s.settingsData("", plaintext))
}

func (s *Server) postTokenDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PostFormValue("id"), 10, 64)
	if err == nil {
		err = s.o.Registry.DeleteToken(id)
	}
	if err != nil {
		s.settingsError(w, r, err)
		return
	}
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

func (s *Server) postCacheFlush(w http.ResponseWriter, r *http.Request) {
	if s.o.Cache != nil {
		s.o.Cache.Flush()
	}
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

// getExport reuses the API's document builder so the two transports cannot
// diverge on what a backup contains.
func (s *Server) getExport(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "yaml"
	}
	if s.o.API == nil {
		http.Error(w, "export unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Disposition", "attachment; filename=kydns-export."+format)
	if err := s.o.API.WriteExport(w, format); err != nil {
		s.o.Logger.Error("export", "error", err)
	}
}
