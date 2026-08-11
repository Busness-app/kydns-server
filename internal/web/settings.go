package web

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/yoshiofthewire/kydns-server/internal/store"
)

type viewRow struct {
	Name        string
	Subnets     string
	Unreachable bool
	References  int
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
		"Views": rows, "Tokens": toks, "NewToken": newToken, "Error": errMsg,
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

func (s *Server) getDiscovered(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "discovered.html", map[string]any{"Title": "Discovered", "Nav": "discovered"})
}
