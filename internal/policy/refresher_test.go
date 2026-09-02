package policy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Busness-app/kydns-server/internal/store"
)

// newRefresher wires a refresher over a real store and a test HTTPS server.
func newRefresher(t *testing.T, srv *httptest.Server) (*store.Store, *Refresher, *Holder) {
	t.Helper()
	st := openStore(t)
	h := NewHolder(func() (store.BlacklistSettings, []store.BlacklistList, []store.BlacklistRule, error) {
		set, err := st.BlacklistSettings()
		if err != nil {
			return set, nil, nil, err
		}
		lists, err := st.BlacklistLists()
		if err != nil {
			return set, nil, nil, err
		}
		rules, err := st.BlacklistRules()
		return set, lists, rules, err
	})
	if err := h.Rebuild(); err != nil {
		t.Fatal(err)
	}
	f := newTestFetcher(t, srv)
	return st, NewRefresher(st, f, h, nil), h
}

func TestRefreshStoresAParsedListAndBlocks(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("# comment\nads.example\nnot a domain\n"))
	}))
	defer srv.Close()
	st, ref, h := newRefresher(t, srv)

	id, err := st.PutBlacklistList(store.BlacklistList{
		Name: "l1", URL: srv.URL, Format: FormatDomains, Enabled: true, IntervalSeconds: 3600,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ref.RefreshList(context.Background(), id); err != nil {
		t.Fatal(err)
	}

	got, err := st.BlacklistListByID(id)
	if err != nil {
		t.Fatal(err)
	}
	if got.EntryCount != 1 || got.SkippedCount != 1 || got.LastError != "" || got.LastOKAt == 0 {
		t.Errorf("= %+v, want 1 entry, 1 skipped, no error", got)
	}
	if blocked, decision, _ := h.Decide("ads.example"); !blocked || decision != "l1" {
		t.Errorf("Decide() = %v %q, want blocked by l1 right after the refresh", blocked, decision)
	}
}

// The property that keeps DNS working when a list host goes down.
func TestFailedRefreshKeepsTheLastGoodSnapshotServing(t *testing.T) {
	var fail atomic.Bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		w.Write([]byte("ads.example\n"))
	}))
	defer srv.Close()
	st, ref, h := newRefresher(t, srv)

	id, err := st.PutBlacklistList(store.BlacklistList{
		Name: "l1", URL: srv.URL, Format: FormatDomains, Enabled: true, IntervalSeconds: 3600,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ref.RefreshList(context.Background(), id); err != nil {
		t.Fatal(err)
	}

	fail.Store(true)
	if err := ref.RefreshList(context.Background(), id); err == nil {
		t.Fatal("RefreshList() succeeded against a failing source")
	}
	got, err := st.BlacklistListByID(id)
	if err != nil {
		t.Fatal(err)
	}
	if got.LastError == "" {
		t.Error("the failure was not recorded")
	}
	if len(got.Snapshot) != 1 {
		t.Errorf("Snapshot = %v, want the last good body retained", got.Snapshot)
	}
	if blocked, _, _ := h.Decide("ads.example"); !blocked {
		t.Error("a failed refresh stopped the name being blocked")
	}
}

// A malformed body is treated exactly like a failed download.
func TestUnparseableBodyKeepsTheLastGoodSnapshot(t *testing.T) {
	var junk atomic.Bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if junk.Load() {
			w.Write([]byte("<html>we moved</html>\n"))
			return
		}
		w.Write([]byte("||ads.example^\n"))
	}))
	defer srv.Close()
	st, ref, h := newRefresher(t, srv)

	id, err := st.PutBlacklistList(store.BlacklistList{
		Name: "l1", URL: srv.URL, Format: FormatAdblock, Enabled: true, IntervalSeconds: 3600,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ref.RefreshList(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	junk.Store(true)
	if err := ref.RefreshList(context.Background(), id); err == nil {
		t.Fatal("RefreshList() accepted a body that produced no usable domains")
	}
	if blocked, _, _ := h.Decide("ads.example"); !blocked {
		t.Error("a junk body dropped the working snapshot")
	}
}

// A refresh failure must never let a secret carried in the list URL's query
// string reach the stored last_error, which the API, the UI and the CLI all
// surface verbatim.
func TestFailedRefreshNeverLeaksAURLSecretIntoLastError(t *testing.T) {
	st := openStore(t)
	h := NewHolder(func() (store.BlacklistSettings, []store.BlacklistList, []store.BlacklistRule, error) {
		set, err := st.BlacklistSettings()
		if err != nil {
			return set, nil, nil, err
		}
		lists, err := st.BlacklistLists()
		if err != nil {
			return set, nil, nil, err
		}
		rules, err := st.BlacklistRules()
		return set, lists, rules, err
	})
	if err := h.Rebuild(); err != nil {
		t.Fatal(err)
	}
	// Port 0 on loopback never accepts a connection, so Fetch fails with a
	// *url.Error whose text embeds this exact URL.
	const secretURL = "https://127.0.0.1:0/list?token=SECRET"
	ref := NewRefresher(st, NewFetcher(2*time.Second), h, nil)

	id, err := st.PutBlacklistList(store.BlacklistList{
		Name: "l1", URL: secretURL, Format: FormatDomains, Enabled: true, IntervalSeconds: 3600,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ref.RefreshList(context.Background(), id); err == nil {
		t.Fatal("RefreshList() succeeded against an unreachable host")
	}
	got, err := st.BlacklistListByID(id)
	if err != nil {
		t.Fatal(err)
	}
	if got.LastError == "" {
		t.Fatal("the failure was not recorded")
	}
	if strings.Contains(got.LastError, "SECRET") || strings.Contains(got.LastError, secretURL) {
		t.Errorf("last_error = %q, leaks the list URL's query string", got.LastError)
	}
}

func TestRefreshDueHonorsTheInterval(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write([]byte("ads.example\n"))
	}))
	defer srv.Close()
	st, ref, _ := newRefresher(t, srv)

	now := time.Unix(1_000_000, 0)
	ref.Now = func() time.Time { return now }
	if _, err := st.PutBlacklistList(store.BlacklistList{
		Name: "l1", URL: srv.URL, Format: FormatDomains, Enabled: true, IntervalSeconds: 3600,
	}); err != nil {
		t.Fatal(err)
	}

	ref.RefreshDue(context.Background())
	ref.RefreshDue(context.Background())
	if hits.Load() != 1 {
		t.Errorf("hits = %d, want 1: the second pass is inside the interval", hits.Load())
	}
	now = now.Add(2 * time.Hour)
	ref.RefreshDue(context.Background())
	if hits.Load() != 2 {
		t.Errorf("hits = %d, want 2 once the interval elapsed", hits.Load())
	}
}

func TestRefreshDueSkipsDisabledLists(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write([]byte("ads.example\n"))
	}))
	defer srv.Close()
	st, ref, _ := newRefresher(t, srv)
	if _, err := st.PutBlacklistList(store.BlacklistList{
		Name: "off", URL: srv.URL, Format: FormatDomains, Enabled: false, IntervalSeconds: 60,
	}); err != nil {
		t.Fatal(err)
	}
	ref.RefreshDue(context.Background())
	if hits.Load() != 0 {
		t.Errorf("hits = %d, want 0 for a disabled list", hits.Load())
	}
}

func TestNotModifiedKeepsTheSnapshotAndClearsTheError(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `W/"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `W/"v1"`)
		w.Write([]byte("ads.example\n"))
	}))
	defer srv.Close()
	st, ref, h := newRefresher(t, srv)
	id, err := st.PutBlacklistList(store.BlacklistList{
		Name: "l1", URL: srv.URL, Format: FormatDomains, Enabled: true, IntervalSeconds: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ref.RefreshList(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if err := ref.RefreshList(context.Background(), id); err != nil {
		t.Fatalf("second RefreshList() (a 304): %v", err)
	}
	got, err := st.BlacklistListByID(id)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Snapshot) != 1 || got.LastError != "" {
		t.Errorf("after a 304 = %+v, want the snapshot kept and no error", got)
	}
	if blocked, _, _ := h.Decide("ads.example"); !blocked {
		t.Error("a 304 dropped the snapshot")
	}
}
