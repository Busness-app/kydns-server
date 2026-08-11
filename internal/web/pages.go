package web

import "net/http"

// pageRoutes registers the application screens. Tasks 18 to 21 fill these in;
// they exist now so the auth middleware has real routes to protect.
func (s *Server) pageRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /", s.requireSession(func(w http.ResponseWriter, r *http.Request) {
		s.render(w, r, "dashboard.html", map[string]any{"Title": "Dashboard", "Nav": "dashboard"})
	}))
	for _, p := range []string{"/services", "/records", "/discovered", "/settings"} {
		title := p[1:]
		mux.HandleFunc("GET "+p, s.requireSession(func(w http.ResponseWriter, r *http.Request) {
			s.render(w, r, title+".html", map[string]any{"Title": title, "Nav": title})
		}))
	}
	mux.HandleFunc("POST /services/new", s.requireCSRF(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/services", http.StatusSeeOther)
	}))
}
