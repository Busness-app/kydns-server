package web

import (
	"net/http"
	"time"
)

// bannerWindow is how far back a CGNAT refusal still counts as current.
const bannerWindow = time.Hour

func (s *Server) getDashboard(w http.ResponseWriter, r *http.Request) {
	data := map[string]any{
		"Title": "Dashboard", "Nav": "dashboard",
		// Exposure is standing state, not an event: it shows on every load.
		"PublicRanges": s.publicRanges(),
		// Nil on a standalone node, which has no role worth a line.
		"ReplicationLine": s.replicationSummary(),
	}

	var banners []*Banner
	if s.o.Upstreams != nil {
		up := s.o.Upstreams()
		data["Upstreams"] = up
		if b := UpstreamsDownBanner(up); b != nil {
			banners = append(banners, b)
		}
		if b := PlaintextUpstreamBanner(up); b != nil {
			banners = append(banners, b)
		}
	}

	views, err := s.o.Registry.Views()
	if err != nil {
		data["Error"] = err.Error()
		data["Banners"] = banners
		s.render(w, r, "dashboard.html", data)
		return
	}
	svcs, err := s.o.Registry.Services()
	if err != nil {
		data["Error"] = err.Error()
	}
	recs, err := s.o.Registry.Records()
	if err != nil {
		data["Error"] = err.Error()
	}

	if b := TailscaleBanner(s.o.ACL, views, s.allowTailscale(), bannerWindow); b != nil {
		banners = append(banners, b)
	}
	data["Banners"] = banners
	data["Services"] = len(svcs)
	data["Records"] = len(recs)
	data["Views"] = len(views)
	if s.o.ACL != nil {
		st := s.o.ACL.Stats()
		data["RefusedTotal"] = st.Total
		data["RefusedCGNAT"] = st.CGNAT
	}
	if s.o.Cache != nil {
		data["CacheEntries"] = s.o.Cache.Len()
	}

	// The traffic numbers are rendered server-side as well as polled, so the
	// page tells the whole story before any script runs.
	m := s.o.Metrics.Snapshot()
	data["Queries"] = m
	data["AvgMS"] = m.AvgMS()
	data["CacheHitRate"] = m.CacheHitRate()
	data["Uptime"] = shortDuration(time.Duration(m.UptimeSeconds) * time.Second)
	data["LastQuery"] = sinceText(m.LastQuery, time.Now())
	if s.o.Policy != nil {
		data["TopBlocked"] = s.o.Policy.TopBlocked(topBlockedShown)
	}
	s.render(w, r, "dashboard.html", data)
}
