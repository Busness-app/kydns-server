package web

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/yoshiofthewire/kydns-server/internal/dnsserver"
	"github.com/yoshiofthewire/kydns-server/internal/store"
)

// restartNote covers exactly the keys the config file still owns. Everything
// else is edited above and stored in the database.
const restartNote = "These come from the config file or the environment, and are read at " +
	"startup. Everything else is edited above and stored in the database, where the " +
	"config file no longer has any effect."

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

// upstreams is nil when the forwarder is not wired, which the template renders
// as "not enabled" rather than as an empty table.
func (s *Server) upstreams() []dnsserver.UpstreamStatus {
	if s.o.Upstreams == nil {
		return nil
	}
	return s.o.Upstreams()
}

// configRows renders the keys the config file still owns: they are all
// needed before the database is open. Every other key moved into the database,
// and showing the file's copy of one would show a value nothing reads.
func (s *Server) configRows() []configRow {
	c := s.o.Config
	if c == nil {
		return nil
	}
	return []configRow{
		{"data_dir", c.DataDir},
		{"dns.listen", c.DNS.Listen},
		{"admin.listen", c.Admin.Listen},
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
	for _, n := range unreachableViews(views, s.allowTailscale()) {
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
	data := map[string]any{
		"Title": "Settings", "Nav": "settings",
		"Views": rows, "Tokens": toks, "NewToken": newToken,
		"Config": s.configRows(), "RestartNote": restartNote, "Error": errMsg,
		"Upstreams":    s.upstreams(),
		"Restart":      s.restartPending(),
		"PublicRanges": s.publicRanges(),
	}
	// Absent rather than zero when the service is not wired: the template then
	// renders the read-only view instead of a form full of empty boxes.
	if v, ok := s.liveSettings(); ok {
		data["Server"] = v
	}
	return data
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
