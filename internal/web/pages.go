package web

import "net/http"

func init() {
	registerPage("dashboard.html")
	registerPage("services.html")
}

// pageRoutes registers the application screens. Tasks 18 to 21 replace these
// placeholders with real handlers.
func (s *Server) pageRoutes(mux *http.ServeMux) {
	mux.Handle("GET /static/", s.StaticHandler())
	mux.HandleFunc("GET /", s.requireSession(s.getDashboard))
	mux.HandleFunc("GET /services", s.requireSession(s.getServices))
	mux.HandleFunc("POST /services/new", s.requireCSRF(s.postServiceNew))
	mux.HandleFunc("POST /services/address", s.requireCSRF(s.postServiceAddress))
	mux.HandleFunc("POST /services/delete", s.requireCSRF(s.postServiceDelete))

	for _, p := range []string{"/records", "/discovered", "/settings"} {
		nav := p[1:]
		mux.HandleFunc("GET "+p, s.requireSession(func(w http.ResponseWriter, r *http.Request) {
			s.render(w, r, "dashboard.html", map[string]any{"Title": nav, "Nav": nav})
		}))
	}
}
