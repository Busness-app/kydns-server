package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Busness-app/kydns-server/internal/dnsserver"
)

// withMetrics attaches live counters to a test server and drives a few queries
// through them, so the JSON under test is the shape the dashboard really gets.
func withMetrics(srv *Server) *dnsserver.Metrics {
	m := dnsserver.NewMetrics()
	srv.o.Metrics = m
	m.Record("authoritative", 0, 0)
	m.Record("forward", 0, 0)
	m.Record("blocked", 3, 0)
	m.RecordCache(true)
	m.RecordCache(false)
	return m
}

func TestStatsJSONReportsQueryCounters(t *testing.T) {
	h, srv := newWeb(t)
	setupAndLogin(t, h)
	c := loginCookie(t, h)
	withMetrics(srv)

	var got struct {
		Queries struct {
			Total         uint64 `json:"total"`
			Authoritative uint64 `json:"authoritative"`
			Forwarded     uint64 `json:"forwarded"`
			Blocked       uint64 `json:"blocked"`
		} `json:"queries"`
		Cache struct {
			HitRate int `json:"hit_rate"`
		} `json:"cache"`
		History []dnsserver.Bucket `json:"history"`
	}
	body := get(t, h, "/stats.json", c).Body.Bytes()
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	if got.Queries.Total != 3 {
		t.Errorf("total = %d, want 3", got.Queries.Total)
	}
	if got.Queries.Authoritative != 1 || got.Queries.Forwarded != 1 || got.Queries.Blocked != 1 {
		t.Errorf("outcome split wrong: %+v", got.Queries)
	}
	if got.Cache.HitRate != 50 {
		t.Errorf("hit rate = %d, want 50", got.Cache.HitRate)
	}
	if len(got.History) == 0 {
		t.Error("no history for the charts to draw")
	}
}

// The charts are the point of the endpoint: an hour of evenly spaced buckets
// has to arrive even on a server that has answered nothing.
func TestStatsJSONHistorySpansAnHourWhenIdle(t *testing.T) {
	h, srv := newWeb(t)
	setupAndLogin(t, h)
	c := loginCookie(t, h)
	srv.o.Metrics = dnsserver.NewMetrics()

	var got struct {
		History []dnsserver.Bucket `json:"history"`
	}
	if err := json.Unmarshal(get(t, h, "/stats.json", c).Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.History) != 60 {
		t.Fatalf("history has %d buckets, want 60", len(got.History))
	}
	for i := 1; i < len(got.History); i++ {
		if got.History[i].Minute != got.History[i-1].Minute+1 {
			t.Fatalf("bucket %d is not one minute after its predecessor", i)
		}
	}
}

// live.js and the route have to name the same path, and nothing else checks it.
func TestLiveJSPollsTheStatsRoute(t *testing.T) {
	b, err := staticFS.ReadFile("static/live.js")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"/stats.json"`) {
		t.Error("live.js does not poll /stats.json")
	}
}

// The charts are drawn by charts.js and driven by live.js, so the dashboard has
// to ship both or the graphs never appear.
func TestDashboardShipsBothScripts(t *testing.T) {
	b, err := templateFS.ReadFile("templates/dashboard.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, src := range []string{"/static/charts.js", "/static/live.js"} {
		if !strings.Contains(string(b), src) {
			t.Errorf("dashboard does not load %s", src)
		}
	}
}

func TestStatsJSONRequiresASession(t *testing.T) {
	h, _ := newWeb(t)
	setupAndLogin(t, h)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/stats.json", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("signed-out /stats.json returned %d, want 401", rec.Code)
	}
}

// Nothing on this endpoint may identify a client. The counters carry no address
// by construction, and this holds that line against a future field.
func TestStatsJSONCarriesNoClientAddress(t *testing.T) {
	h, srv := newWeb(t)
	setupAndLogin(t, h)
	c := loginCookie(t, h)
	withMetrics(srv)

	body := get(t, h, "/stats.json", c).Body.String()
	for _, leak := range []string{"client", "192.168.", "127.0.0.", "100.64."} {
		if strings.Contains(body, leak) {
			t.Errorf("/stats.json contains %q:\n%s", leak, body)
		}
	}
}
