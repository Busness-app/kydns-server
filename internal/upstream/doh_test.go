package upstream

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func dohServer(t *testing.T, cert tls.Certificate, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// dohEcho replies with the standard answer and records what it received.
func dohEcho(t *testing.T, seen *dns.Msg) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, dns.MaxMsgSize))
		if err != nil {
			t.Error(err)
			return
		}
		if err := seen.Unpack(body); err != nil {
			t.Error(err)
			return
		}
		wire, err := answer(seen).Pack()
		if err != nil {
			t.Error(err)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(wire)
	}
}

func dohSpec(t *testing.T, srv *httptest.Server, pool *x509.CertPool) Spec {
	t.Helper()
	s, err := Parse(srv.URL + "/dns-query")
	if err != nil {
		t.Fatal(err)
	}
	s.RootCAs = pool
	return s
}

func TestDoHRoundTrip(t *testing.T) {
	cert, pool := testCert(t)
	seen := new(dns.Msg)
	srv := dohServer(t, cert, dohEcho(t, seen))

	u, err := New(dohSpec(t, srv, pool), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !u.Secure() {
		t.Error("Secure() = false for DoH")
	}
	resp, err := u.Exchange(context.Background(), query())
	wantAnswer(t, resp, err)
}

// RFC 8484 section 4.1: the id is zero on the wire. The caller still gets its
// own id back, because the rest of KyDNS matches on it.
func TestDoHZeroesTheWireID(t *testing.T) {
	cert, pool := testCert(t)
	seen := new(dns.Msg)
	srv := dohServer(t, cert, dohEcho(t, seen))

	u, _ := New(dohSpec(t, srv, pool), 2*time.Second)
	req := query()
	req.Id = 4242
	resp, err := u.Exchange(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if seen.Id != 0 {
		t.Errorf("wire id = %d, want 0", seen.Id)
	}
	if resp.Id != 4242 {
		t.Errorf("response id = %d, want the caller's 4242", resp.Id)
	}
}

func TestDoHPostsTheRightHeaders(t *testing.T) {
	cert, pool := testCert(t)
	var method, contentType, accept string
	seen := new(dns.Msg)
	echo := dohEcho(t, seen)
	srv := dohServer(t, cert, func(w http.ResponseWriter, r *http.Request) {
		method, contentType, accept = r.Method, r.Header.Get("Content-Type"), r.Header.Get("Accept")
		echo(w, r)
	})

	u, _ := New(dohSpec(t, srv, pool), 2*time.Second)
	if _, err := u.Exchange(context.Background(), query()); err != nil {
		t.Fatal(err)
	}
	if method != http.MethodPost {
		t.Errorf("method = %q, want POST", method)
	}
	if contentType != "application/dns-message" {
		t.Errorf("Content-Type = %q", contentType)
	}
	if accept != "application/dns-message" {
		t.Errorf("Accept = %q", accept)
	}
}

func TestDoHRejectsBadResponses(t *testing.T) {
	cert, pool := testCert(t)
	for name, tc := range map[string]struct {
		handler http.HandlerFunc
		want    string
	}{
		"non-200": {func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "nope", http.StatusInternalServerError)
		}, "500"},
		"wrong content type": {func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte("<html>"))
		}, "content type"},
		"oversized body": {func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/dns-message")
			w.Write(make([]byte, dns.MaxMsgSize+5000))
		}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			srv := dohServer(t, cert, tc.handler)
			u, _ := New(dohSpec(t, srv, pool), 2*time.Second)
			_, err := u.Exchange(context.Background(), query())
			if err == nil {
				t.Fatal("Exchange() error = nil")
			}
			if tc.want != "" && !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestDoHRejectsUntrustedCertificate(t *testing.T) {
	cert, _ := testCert(t)
	seen := new(dns.Msg)
	srv := dohServer(t, cert, dohEcho(t, seen))

	u, _ := New(dohSpec(t, srv, x509.NewCertPool()), 2*time.Second)
	if _, err := u.Exchange(context.Background(), query()); err == nil {
		t.Fatal("Exchange() error = nil against an untrusted certificate")
	}
}

// The socket goes to the configured IP; only the URL and SNI carry the name.
func TestDoHDialsThePinnedAddress(t *testing.T) {
	cert, pool := testCert(t, "dns.example.test")
	seen := new(dns.Msg)
	echo := dohEcho(t, seen)
	var sni string
	srv := dohServer(t, cert, func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil {
			sni = r.TLS.ServerName
		}
		echo(w, r)
	})

	s, err := Parse(srv.URL + "/dns-query#dns.example.test")
	if err != nil {
		t.Fatal(err)
	}
	s.RootCAs = pool
	if !strings.Contains(s.URL, "dns.example.test") {
		t.Fatalf("URL = %q, want the server name", s.URL)
	}
	u, _ := New(s, 2*time.Second)
	resp, err := u.Exchange(context.Background(), query())
	wantAnswer(t, resp, err)
	// testCert also covers 127.0.0.1, the dialled address, so a handshake
	// that verified against the wrong name would still pass. Only the SNI
	// the server actually saw proves the configured name was used.
	if sni != "dns.example.test" {
		t.Errorf("SNI = %q, want %q", sni, "dns.example.test")
	}
}
