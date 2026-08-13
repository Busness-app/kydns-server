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
	s.render(w, r, "dashboard.html", data)
}
