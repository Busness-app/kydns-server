package policy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newTestFetcher(t *testing.T, srv *httptest.Server) *Fetcher {
	t.Helper()
	f := NewFetcher(5 * time.Second)
	// The test server uses a self-signed certificate; reuse its client so
	// verification stays on in production code and on in the test.
	f.Client.Transport = srv.Client().Transport
	return f
}

func TestFetchReturnsBodyAndValidators(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `W/"v1"`)
		w.Header().Set("Last-Modified", "Mon, 01 Jan 2026 00:00:00 GMT")
		w.Write([]byte("ads.example\n"))
	}))
	defer srv.Close()

	got, err := newTestFetcher(t, srv).Fetch(context.Background(), srv.URL, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Body) != "ads.example\n" {
		t.Errorf("Body = %q", got.Body)
	}
	if got.ETag != `W/"v1"` || got.LastModified == "" {
		t.Errorf("validators = %q / %q, want both captured", got.ETag, got.LastModified)
	}
	if got.NotModified {
		t.Error("NotModified = true on a 200")
	}
}

func TestFetchSendsValidatorsAndHandles304(t *testing.T) {
	var gotETag, gotSince, gotUA, gotCookie string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotETag = r.Header.Get("If-None-Match")
		gotSince = r.Header.Get("If-Modified-Since")
		gotUA = r.Header.Get("User-Agent")
		gotCookie = r.Header.Get("Cookie")
		w.WriteHeader(http.StatusNotModified)
	}))
	defer srv.Close()

	got, err := newTestFetcher(t, srv).Fetch(context.Background(), srv.URL, `W/"v1"`, "Mon, 01 Jan 2026 00:00:00 GMT")
	if err != nil {
		t.Fatal(err)
	}
	if !got.NotModified || got.Body != nil {
		t.Errorf("= %+v, want NotModified with no body", got)
	}
	if gotETag != `W/"v1"` || gotSince == "" {
		t.Errorf("sent validators %q / %q, want both", gotETag, gotSince)
	}
	// Nothing that identifies this installation or its users may go out.
	if gotUA != "kydns" {
		t.Errorf("User-Agent = %q, want the fixed %q", gotUA, "kydns")
	}
	if gotCookie != "" {
		t.Errorf("Cookie = %q, want none", gotCookie)
	}
}

func TestFetchRefusesPlainHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ads.example\n"))
	}))
	defer srv.Close()
	if _, err := NewFetcher(time.Second).Fetch(context.Background(), srv.URL, "", ""); err == nil {
		t.Error("Fetch() accepted an http:// URL")
	}
}

func TestFetchRefusesARedirectOffHTTPS(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ads.example\n"))
	}))
	defer plain.Close()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL, http.StatusFound)
	}))
	defer srv.Close()
	if _, err := newTestFetcher(t, srv).Fetch(context.Background(), srv.URL, "", ""); err == nil {
		t.Error("Fetch() followed a redirect to plain HTTP")
	}
}

func TestFetchRefusesAnEndlessRedirectChain(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL+"/again", http.StatusFound)
	}))
	defer srv.Close()
	if _, err := newTestFetcher(t, srv).Fetch(context.Background(), srv.URL, "", ""); err == nil {
		t.Error("Fetch() followed redirects without limit")
	}
}

func TestFetchRefusesAnOversizedBody(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for i := 0; i < 200; i++ {
			w.Write([]byte(strings.Repeat("x", 1024)))
		}
	}))
	defer srv.Close()
	f := newTestFetcher(t, srv)
	f.MaxBytes = 4096
	if _, err := f.Fetch(context.Background(), srv.URL, "", ""); err == nil {
		t.Error("Fetch() accepted a body past the ceiling")
	}
}

func TestFetchReportsAnErrorStatus(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "gone", http.StatusNotFound)
	}))
	defer srv.Close()
	if _, err := newTestFetcher(t, srv).Fetch(context.Background(), srv.URL, "", ""); err == nil {
		t.Error("Fetch() accepted a 404")
	}
}
