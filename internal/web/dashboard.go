package web

import (
	"net/http"
	"time"
)

// bannerWindow is how far back a CGNAT refusal still counts as current.
const bannerWindow = time.Hour

func (s *Server) getDashboard(w http.ResponseWriter, r *http.Request) {
	data := map[string]any{"Title": "Dashboard", "Nav": "dashboard", "Upstreams": s.o.Upstreams}

	views, err := s.o.Registry.Views()
	if err != nil {
		data["Error"] = err.Error()
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

	data["Banner"] = TailscaleBanner(s.o.ACL, views, s.o.AllowTailscale, bannerWindow)
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
