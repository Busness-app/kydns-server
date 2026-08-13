package web

import "net/http"

func init() {
	registerPage("dashboard.html")
	registerPage("services.html")
	registerPage("records.html")
	registerPage("settings.html")
	registerPage("discovered.html")
	registerPage("blacklists.html")
}

// pageRoutes registers the application screens.
func (s *Server) pageRoutes(mux *http.ServeMux) {
	mux.Handle("GET /static/", s.StaticHandler())
	mux.HandleFunc("GET /license", s.getLicense)

	mux.HandleFunc("GET /", s.requireSession(s.getDashboard))

	mux.HandleFunc("GET /services", s.requireSession(s.getServices))
	mux.HandleFunc("POST /services/new", s.requireCSRF(s.postServiceNew))
	mux.HandleFunc("POST /services/address", s.requireCSRF(s.postServiceAddress))
	mux.HandleFunc("POST /services/routing", s.requireCSRF(s.postServiceRouting))
	mux.HandleFunc("POST /services/delete", s.requireCSRF(s.postServiceDelete))

	mux.HandleFunc("GET /records", s.requireSession(s.getRecords))
	mux.HandleFunc("POST /records/new", s.requireCSRF(s.postRecordNew))
	mux.HandleFunc("POST /records/delete", s.requireCSRF(s.postRecordDelete))

	mux.HandleFunc("GET /discovered", s.requireSession(s.getDiscovered))
	mux.HandleFunc("POST /discovered/promote", s.requireCSRF(s.postPromote))

	mux.HandleFunc("GET /blacklists", s.requireSession(s.getBlacklists))
	mux.HandleFunc("POST /blacklists/toggle", s.requireCSRF(s.postBlacklistToggle))
	mux.HandleFunc("POST /blacklists/lists/new", s.requireCSRF(s.postBlacklistListNew))
	mux.HandleFunc("POST /blacklists/lists/toggle", s.requireCSRF(s.postBlacklistListToggle))
	mux.HandleFunc("POST /blacklists/lists/delete", s.requireCSRF(s.postBlacklistListDelete))
	mux.HandleFunc("POST /blacklists/refresh", s.requireCSRF(s.postBlacklistRefresh))
	mux.HandleFunc("POST /blacklists/rules/new", s.requireCSRF(s.postBlacklistRuleNew))
	mux.HandleFunc("POST /blacklists/rules/delete", s.requireCSRF(s.postBlacklistRuleDelete))
	mux.HandleFunc("POST /blacklists/test", s.requireCSRF(s.postBlacklistTest))

	mux.HandleFunc("GET /settings", s.requireSession(s.getSettings))
	mux.HandleFunc("GET /settings/export", s.requireSession(s.getExport))
	mux.HandleFunc("POST /settings/server", s.requireCSRF(s.postServerSettings))
	mux.HandleFunc("POST /settings/views/new", s.requireCSRF(s.postViewNew))
	mux.HandleFunc("POST /settings/views/delete", s.requireCSRF(s.postViewDelete))
	mux.HandleFunc("POST /settings/tokens/new", s.requireCSRF(s.postTokenNew))
	mux.HandleFunc("POST /settings/tokens/delete", s.requireCSRF(s.postTokenDelete))
	mux.HandleFunc("POST /settings/cache/flush", s.requireCSRF(s.postCacheFlush))
}
