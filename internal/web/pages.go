package web

func init() {
	registerPage("dashboard.html")
	registerPage("services.html")
	registerPage("records.html")
	registerPage("settings.html")
	registerPage("discovered.html")
	registerPage("blacklists.html")
	registerPage("dhcp.html")
	registerPage("replication.html")
}

// pageRoutes registers the application screens.
func (s *Server) pageRoutes(mux registrar) {
	mux.Handle("GET /static/", s.StaticHandler())
	mux.HandleFunc("GET /license", s.getLicense)

	mux.HandleFunc("GET /", s.requireSession(s.getDashboard))
	mux.HandleFunc("GET /stats.json", s.requireSessionJSON(s.getStatsJSON))

	mux.HandleFunc("GET /services", s.requireSession(s.getServices))
	mux.HandleFunc("GET /services/health.json", s.requireSessionJSON(s.getHealthJSON))
	mux.HandleFunc("POST /services/new", s.requireCSRF(s.postServiceNew))
	mux.HandleFunc("POST /services/address", s.requireCSRF(s.postServiceAddress))
	mux.HandleFunc("POST /services/routing", s.requireCSRF(s.postServiceRouting))
	mux.HandleFunc("POST /services/delete", s.requireCSRF(s.postServiceDelete))

	mux.HandleFunc("GET /records", s.requireSession(s.getRecords))
	mux.HandleFunc("POST /records/new", s.requireCSRF(s.postRecordNew))
	mux.HandleFunc("POST /records/delete", s.requireCSRF(s.postRecordDelete))

	mux.HandleFunc("GET /discovered", s.requireSession(s.getDiscovered))
	mux.HandleFunc("POST /discovered/promote", s.requireCSRF(s.postPromote))

	mux.HandleFunc("GET /dhcp", s.requireSession(s.getDHCP))
	mux.HandleFunc("POST "+PathDHCPSettings, s.requireCSRF(s.postDHCPSettings))
	mux.HandleFunc("POST "+PathDHCPSuggest, s.requireCSRF(s.postDHCPSuggest))
	mux.HandleFunc("POST /dhcp/reserve", s.requireCSRF(s.postDHCPReserve))

	mux.HandleFunc("GET /blacklists", s.requireSession(s.getBlacklists))
	mux.HandleFunc("POST /blacklists/toggle", s.requireCSRF(s.postBlacklistToggle))
	mux.HandleFunc("POST /blacklists/lists/new", s.requireCSRF(s.postBlacklistListNew))
	mux.HandleFunc("POST /blacklists/lists/toggle", s.requireCSRF(s.postBlacklistListToggle))
	mux.HandleFunc("POST /blacklists/lists/delete", s.requireCSRF(s.postBlacklistListDelete))
	mux.HandleFunc("POST /blacklists/refresh", s.requireCSRF(s.postBlacklistRefresh))
	mux.HandleFunc("POST /blacklists/rules/new", s.requireCSRF(s.postBlacklistRuleNew))
	mux.HandleFunc("POST /blacklists/rules/delete", s.requireCSRF(s.postBlacklistRuleDelete))
	mux.HandleFunc("POST /blacklists/test", s.requireCSRF(s.postBlacklistTest))

	mux.HandleFunc("GET /replication", s.requireSession(s.getReplication))
	mux.HandleFunc("POST /replication/invite", s.requireCSRF(s.postReplicaInvite))
	mux.HandleFunc("POST /replication/remove", s.requireCSRF(s.postReplicaRemove))
	// PathPromote, not a path of this file's own choosing: the web write gate
	// exempts that constant, and a button anywhere else is refused with 409 on
	// the one node that needs it.
	mux.HandleFunc("POST "+PathPromote, s.requireCSRF(s.postReplicaPromote))
	mux.HandleFunc("POST "+PathJoin, s.requireCSRF(s.postReplicaJoin))

	mux.HandleFunc("GET /settings", s.requireSession(s.getSettings))
	mux.HandleFunc("GET /settings/export", s.requireSession(s.getExport))
	mux.HandleFunc("GET /settings/backup/export", s.requireSession(s.getBackupExport))
	mux.HandleFunc("POST /settings/backup/pair", s.requireCSRF(s.postBackupPair))
	mux.HandleFunc("POST /settings/backup/deposit", s.requireCSRF(s.postBackupDeposit))
	mux.HandleFunc("POST /settings/backup/drill", s.requireCSRF(s.postBackupDrill))
	mux.HandleFunc("POST /settings/server", s.requireCSRF(s.postServerSettings))
	mux.HandleFunc("POST /settings/views/new", s.requireCSRF(s.postViewNew))
	mux.HandleFunc("POST /settings/views/delete", s.requireCSRF(s.postViewDelete))
	mux.HandleFunc("POST /settings/tokens/new", s.requireCSRF(s.postTokenNew))
	mux.HandleFunc("POST /settings/tokens/delete", s.requireCSRF(s.postTokenDelete))
	mux.HandleFunc("POST /settings/cache/flush", s.requireCSRF(s.postCacheFlush))
	mux.HandleFunc("POST /settings/sso", s.requireCSRF(s.postSSOSettings))
	mux.HandleFunc("POST /settings/sso/unlink", s.requireCSRF(s.postSSOUnlink))
}
