package web

import (
	"encoding/json"
	"net/http"
)

// topBlockedShown is how many blocked names the dashboard card lists.
const topBlockedShown = 10

// statsPayload is what the dashboard polls. Every field is a count or a
// timestamp: the payload cannot name a client because there is no client
// identity in the counters it reads.
func (s *Server) statsPayload() map[string]any {
	m := s.o.Metrics.Snapshot()
	out := map[string]any{
		"queries": map[string]any{
			"total":         m.Total,
			"authoritative": m.Authoritative,
			"forwarded":     m.Forwarded,
			"blocked":       m.Blocked,
			"refused":       m.Refused,
			"errors":        m.Errors,
			"noerror":       m.NoError,
			"nxdomain":      m.NXDomain,
			"servfail":      m.ServFail,
			"avg_ms":        m.AvgMS(),
			"last_query":    m.LastQuery,
		},
		"cache": map[string]any{
			"hits": m.CacheHits, "misses": m.CacheMisses, "hit_rate": m.CacheHitRate(),
		},
		"uptime_seconds": m.UptimeSeconds,
		"history":        m.History,
	}
	if s.o.Cache != nil {
		out["cache"].(map[string]any)["entries"] = s.o.Cache.Len()
	}
	if s.o.ACL != nil {
		st := s.o.ACL.Stats()
		out["refusals"] = map[string]any{"total": st.Total, "cgnat": st.CGNAT}
	}
	if s.o.Policy != nil {
		out["top_blocked"] = s.o.Policy.TopBlocked(topBlockedShown)
	}
	return out
}

// getStatsJSON feeds the dashboard's live numbers and charts. Like
// /services/health.json it takes the session cookie, not an API token.
func (s *Server) getStatsJSON(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(s.statsPayload()); err != nil {
		s.o.Logger.Error("encode stats", "error", err)
	}
}
