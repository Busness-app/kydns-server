package upstream

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	for _, tc := range []struct {
		raw        string
		transport  Transport
		addr       string
		serverName string
		url        string
	}{
		{"1.1.1.1:53", Plain, "1.1.1.1:53", "", ""},
		{"udp://192.168.1.1", Plain, "192.168.1.1:53", "", ""},
		{"udp://192.168.1.1:5353", Plain, "192.168.1.1:5353", "", ""},
		{"tls://1.1.1.1", DoT, "1.1.1.1:853", "", ""},
		{"tls://9.9.9.9:853", DoT, "9.9.9.9:853", "", ""},
		{"tls://45.90.28.0:853#abc.dns.nextdns.io", DoT, "45.90.28.0:853", "abc.dns.nextdns.io", ""},
		{"https://9.9.9.9", DoH, "9.9.9.9:443", "", "https://9.9.9.9/dns-query"},
		{"https://9.9.9.9/resolve", DoH, "9.9.9.9:443", "", "https://9.9.9.9/resolve"},
		{"https://9.9.9.9:8443/dns-query", DoH, "9.9.9.9:8443", "", "https://9.9.9.9:8443/dns-query"},
		{"https://45.90.28.0#abc.dns.nextdns.io", DoH, "45.90.28.0:443", "abc.dns.nextdns.io", "https://abc.dns.nextdns.io/dns-query"},
		{"tls://[2606:4700:4700::1111]:853", DoT, "[2606:4700:4700::1111]:853", "", ""},
		{"https://[2606:4700:4700::1111]", DoH, "[2606:4700:4700::1111]:443", "", "https://[2606:4700:4700::1111]/dns-query"},
	} {
		got, err := Parse(tc.raw)
		if err != nil {
			t.Errorf("Parse(%q) error = %v", tc.raw, err)
			continue
		}
		if got.Raw != tc.raw {
			t.Errorf("Parse(%q).Raw = %q", tc.raw, got.Raw)
		}
		if got.Transport != tc.transport {
			t.Errorf("Parse(%q).Transport = %v, want %v", tc.raw, got.Transport, tc.transport)
		}
		if got.Addr != tc.addr {
			t.Errorf("Parse(%q).Addr = %q, want %q", tc.raw, got.Addr, tc.addr)
		}
		if got.ServerName != tc.serverName {
			t.Errorf("Parse(%q).ServerName = %q, want %q", tc.raw, got.ServerName, tc.serverName)
		}
		if got.URL != tc.url {
			t.Errorf("Parse(%q).URL = %q, want %q", tc.raw, got.URL, tc.url)
		}
	}
}

// A hostname upstream would need DNS to bootstrap DNS. The error has to say so,
// because the fix is not obvious.
func TestParseRejectsHostname(t *testing.T) {
	for _, raw := range []string{"tls://dns.quad9.net:853", "https://cloudflare-dns.com/dns-query", "dns.google:53"} {
		_, err := Parse(raw)
		if err == nil {
			t.Errorf("Parse(%q) error = nil, want a rejection", raw)
			continue
		}
		if !strings.Contains(err.Error(), "DNS cannot bootstrap DNS") {
			t.Errorf("Parse(%q) error = %v, want the bootstrap explanation", raw, err)
		}
	}
}

func TestParseRejectsBadInput(t *testing.T) {
	for _, raw := range []string{"", "   ", "1.1.1.1:no", "quic://1.1.1.1:853", "tls://1.1.1.1:99999"} {
		if _, err := Parse(raw); err == nil {
			t.Errorf("Parse(%q) error = nil, want a rejection", raw)
		}
	}
}

// The rejection must name the schemes that would have worked.
func TestParseUnknownSchemeNamesTheAlternatives(t *testing.T) {
	_, err := Parse("quic://1.1.1.1:853")
	if err == nil {
		t.Fatal("Parse() error = nil")
	}
	for _, want := range []string{"udp://", "tls://", "https://"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %v does not mention %q", err, want)
		}
	}
}

// Credentials never authenticated anything — the request URL is built from
// Spec.Addr — but Raw kept them verbatim, and String() carries Raw into logs,
// into LastError, and onto two web pages. Rejecting them closes both halves.
func TestParseRejectsCredentials(t *testing.T) {
	for _, raw := range []string{
		"https://user:hunter2@1.1.1.1/dns-query",
		"tls://user:hunter2@1.1.1.1:853",
		"udp://user@192.168.1.1:53",
	} {
		_, err := Parse(raw)
		if err == nil {
			t.Errorf("Parse(%q) error = nil, want a rejection", raw)
			continue
		}
		if !strings.Contains(err.Error(), "credentials are not supported") {
			t.Errorf("Parse(%q) error = %v, want the credential rejection", raw, err)
		}
		if strings.Contains(err.Error(), "hunter2") {
			t.Errorf("Parse(%q) error = %v, which leaks the password it rejected", raw, err)
		}
	}
}

func TestTransportSecure(t *testing.T) {
	for tr, want := range map[Transport]bool{Plain: false, DoT: true, DoH: true} {
		if got := tr.Secure(); got != want {
			t.Errorf("%v.Secure() = %v, want %v", tr, got, want)
		}
	}
}

func TestParseAllStopsAtTheFirstBadEntry(t *testing.T) {
	specs, err := ParseAll([]string{"tls://1.1.1.1:853", "udp://192.168.1.1:53"})
	if err != nil {
		t.Fatal(err)
	}
	if len(specs) != 2 {
		t.Fatalf("ParseAll() returned %d specs, want 2", len(specs))
	}
	if _, err := ParseAll([]string{"tls://1.1.1.1:853", "nope://x"}); err == nil {
		t.Error("ParseAll() error = nil with a bad entry")
	}
}
