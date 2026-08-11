package web

import "net/http"

func init() {
	registerPage("dashboard.html")
	registerPage("services.html")
	registerPage("records.html")
	registerPage("settings.html")
	registerPage("discovered.html")
}

// pageRoutes registers the application screens.
func (s *Server) pageRoutes(mux *http.ServeMux) {
	mux.Handle("GET /static/", s.StaticHandler())

	mux.HandleFunc("GET /", s.requireSession(s.getDashboard))

	mux.HandleFunc("GET /services", s.requireSession(s.getServices))
	mux.HandleFunc("POST /services/new", s.requireCSRF(s.postServiceNew))
	mux.HandleFunc("POST /services/address", s.requireCSRF(s.postServiceAddress))
	mux.HandleFunc("POST /services/delete", s.requireCSRF(s.postServiceDelete))

	mux.HandleFunc("GET /records", s.requireSession(s.getRecords))
	mux.HandleFunc("POST /records/new", s.requireCSRF(s.postRecordNew))
	mux.HandleFunc("POST /records/delete", s.requireCSRF(s.postRecordDelete))

	mux.HandleFunc("GET /discovered", s.requireSession(s.getDiscovered))

	mux.HandleFunc("GET /settings", s.requireSession(s.getSettings))
	mux.HandleFunc("GET /settings/export", s.requireSession(s.getExport))
	mux.HandleFunc("POST /settings/views/new", s.requireCSRF(s.postViewNew))
	mux.HandleFunc("POST /settings/views/delete", s.requireCSRF(s.postViewDelete))
	mux.HandleFunc("POST /settings/tokens/new", s.requireCSRF(s.postTokenNew))
	mux.HandleFunc("POST /settings/tokens/delete", s.requireCSRF(s.postTokenDelete))
	mux.HandleFunc("POST /settings/cache/flush", s.requireCSRF(s.postCacheFlush))
}
