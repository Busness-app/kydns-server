package adminapi

import (
	"net/http"
	"path/filepath"
	"testing"

	"github.com/Busness-app/kydns-server/internal/dnsserver"
	"github.com/Busness-app/kydns-server/internal/registry"
	"github.com/Busness-app/kydns-server/internal/store"
)

// The dashboard and the API read the same counters. If /api/v1/stats reported a
// different number from the screen, one of them would be wrong and there would
// be no way to tell which.
func TestStatsReportsQueryCounters(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "kydns.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	reg := registry.New(s, "home.arpa.", func() error { return nil })
	tok, err := reg.CreateToken("test")
	if err != nil {
		t.Fatal(err)
	}
	m := dnsserver.NewMetrics()
	m.Record("authoritative", 0, 0)
	m.Record("forward", 0, 0)
	m.RecordCache(true)
	h := NewAPI(reg, nil, nil).WithMetrics(m).Handler()

	rec := do(t, h, "GET", "/api/v1/stats", tok, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("= %d: %s", rec.Code, rec.Body)
	}
	got := decodeBody(t, rec)
	q, ok := got["queries"].(map[string]any)
	if !ok {
		t.Fatalf("no queries block: %v", got)
	}
	if q["total"] != float64(2) {
		t.Errorf("total = %v, want 2", q["total"])
	}
	if q["authoritative"] != float64(1) || q["forwarded"] != float64(1) {
		t.Errorf("outcome split wrong: %v", q)
	}
	if got["history"] == nil {
		t.Error("no history block for a client to graph")
	}
}

// Without metrics wired the endpoint still answers rather than panicking: the
// CLI reads it on servers where the DNS side is not running.
func TestStatsWithoutMetricsStillAnswers(t *testing.T) {
	h, tok := newAPI(t)
	if rec := do(t, h, "GET", "/api/v1/stats", tok, ""); rec.Code != http.StatusOK {
		t.Errorf("= %d: %s", rec.Code, rec.Body)
	}
}
