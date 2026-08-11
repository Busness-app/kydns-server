package web

import "net/http"

func init() { registerPage("dashboard.html") }

// pageRoutes registers the application screens. Tasks 18 to 21 replace these
// placeholders with real handlers.
func (s *Server) pageRoutes(mux *http.ServeMux) {
	mux.Handle("GET /static/", s.StaticHandler())
	mux.HandleFunc("GET /", s.requireSession(func(w http.ResponseWriter, r *http.Request) {
		s.render(w, r, "dashboard.html", map[string]any{"Title": "Dashboard", "Nav": "dashboard"})
	}))
	for _, p := range []string{"/services", "/records", "/discovered", "/settings"} {
		nav := p[1:]
		mux.HandleFunc("GET "+p, s.requireSession(func(w http.ResponseWriter, r *http.Request) {
			s.render(w, r, "dashboard.html", map[string]any{"Title": nav, "Nav": nav})
		}))
	}
	mux.HandleFunc("POST /services/new", s.requireCSRF(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/services", http.StatusSeeOther)
	}))
}
