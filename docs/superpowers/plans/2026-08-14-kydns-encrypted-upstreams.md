# KyDNS Encrypted Upstreams Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Forward queries to upstream resolvers over DNS-over-TLS and DNS-over-HTTPS, and pass the upstream's `AD` verdict to clients only when the channel that carried it was encrypted.

**Architecture:** A new `internal/upstream` package parses each configured upstream string and turns it into an `Upstream` — one of three implementations chosen by URL scheme. The scheme is the security policy: `tls://` and `https://` are authenticated and encrypted, `udp://` and a bare `host:port` are not. `dnsserver.Forwarder` holds `[]upstream.Upstream`, clears `AD` at the moment any answer arrives from an insecure upstream, and records the last error per upstream so the UI can say why strict mode is failing.

**Tech Stack:** Go 1.26.5, `github.com/miekg/dns` v1.1.72, `crypto/tls`, `net/http`. No new dependencies.

## Global Constraints

- KyDNS does **not** become a validating resolver. It never verifies an RRSIG, walks a chain of trust, or holds a trust anchor. It trusts the upstream's `AD` bit over an encrypted channel. Nothing in this plan may imply otherwise, in code, comments, UI copy, or docs.
- **No `insecure_skip_verify`, ever.** Certificate verification is always on against the system root pool. The only override is `Spec.RootCAs`, which production leaves nil and tests set to trust a self-signed server.
- **An upstream host must be an IP address.** A hostname would need DNS to bootstrap DNS.
- **`CD` toward the upstream is always 0.** A client may not ask KyDNS to skip upstream validation.
- **`AD` toward the client is cleared at the source** for any answer from an insecure upstream, before caching, so no downstream code has to remember.
- `CGO_ENABLED=0` must keep building. No cgo-requiring dependencies.
- Every task must leave `go build ./...`, `go vet ./...`, `gofmt -l .` and `go test ./...` clean. Task boundaries never leave the tree broken.
- Code style follows `/home/yoshi/.claude/CLAUDE.md`: YAGNI, short meaningful comments, no comment block defending why code is not wrong.

## File Structure

**Created:**

| File | Responsibility |
|---|---|
| `internal/upstream/parse.go` | `Transport`, `Spec`, `Parse`, `ParseAll` — the accepted grammar, defined once |
| `internal/upstream/upstream.go` | The `Upstream` interface, `New`, `NewAll` |
| `internal/upstream/plain.go` | UDP with TCP retry on truncation |
| `internal/upstream/pool.go` | Idle TLS connection free list for DoT |
| `internal/upstream/dot.go` | DNS-over-TLS |
| `internal/upstream/doh.go` | DNS-over-HTTPS |
| `internal/upstream/parse_test.go`, `plain_test.go`, `dot_test.go`, `doh_test.go`, `testhelp_test.go` | Tests and the shared certificate/server helpers |

**Modified:**

| File | Change |
|---|---|
| `internal/dnsserver/cache.go` | `cacheKey` gains `do`; `Get`/`Put` take it |
| `internal/dnsserver/forward.go` | `[]upstream.Upstream`, `Resolve(ctx, q, do)`, `AD` policy, `Status()`. `Exchanger` and `UDPExchanger` deleted |
| `internal/dnsserver/server.go` | Reads `DO` off the request, strips `OPT` for non-EDNS clients |
| `internal/config/config.go` | Encrypted defaults; validation delegates to `upstream.Parse` |
| `internal/web/middleware.go` | `Upstreams` becomes a status func |
| `internal/web/banner.go` | Plaintext-upstream banner |
| `internal/web/dashboard.go`, `templates/dashboard.html` | Banner list, upstream transports |
| `internal/web/settings.go`, `templates/settings.html` | Upstream table with last error |
| `internal/app/serve.go` | Builds upstreams, passes the status func |
| `kydns.example.yaml`, `README.md`, `.github/workflows/ci.yml` | Documentation and the end-to-end DoT check |

---

## Task 1: Upstream spec parsing

**Files:**
- Create: `internal/upstream/parse.go`
- Test: `internal/upstream/parse_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `type Transport int` with constants `Plain`, `DoT`, `DoH`; methods `String() string` and `Secure() bool`
  - `type Spec struct { Raw string; Transport Transport; Addr string; ServerName string; URL string; RootCAs *x509.CertPool }`
  - `func Parse(raw string) (Spec, error)`
  - `func ParseAll(raws []string) ([]Spec, error)`

- [ ] **Step 1: Write the failing test**

Create `internal/upstream/parse_test.go`:

```go
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
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/upstream/`
Expected: FAIL — the package does not exist yet.

- [ ] **Step 3: Write the implementation**

Create `internal/upstream/parse.go`:

```go
// Package upstream turns configured upstream strings into resolvers. The
// scheme in the string is the security policy: tls:// and https:// are
// authenticated and encrypted, udp:// and a bare host:port are not.
package upstream

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
)

type Transport int

const (
	Plain Transport = iota
	DoT
	DoH
)

func (t Transport) String() string {
	switch t {
	case DoT:
		return "DoT"
	case DoH:
		return "DoH"
	default:
		return "plaintext"
	}
}

// Secure reports whether the transport authenticates and encrypts the channel.
// Only a secure transport may carry an AD bit through to a client.
func (t Transport) Secure() bool { return t == DoT || t == DoH }

// Spec is a parsed upstream. Addr is always what gets dialed; ServerName and
// URL only decide what the peer is asked to be.
type Spec struct {
	Raw        string
	Transport  Transport
	Addr       string
	ServerName string
	URL        string // DoH only

	// RootCAs overrides the system trust store. Production leaves it nil;
	// tests set it to trust a self-signed server certificate.
	RootCAs *x509.CertPool
}

func (s Spec) Secure() bool   { return s.Transport.Secure() }
func (s Spec) String() string { return s.Raw }

const bootstrapHint = "host must be an IP address — DNS cannot bootstrap DNS. " +
	"Use the provider's IP, and add #servername if its certificate needs a hostname"

// Parse turns one configured string into a Spec.
func Parse(raw string) (Spec, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return Spec{}, errors.New("upstream is empty")
	}
	if !strings.Contains(s, "://") {
		addr, err := hostPort(s, "53")
		if err != nil {
			return Spec{}, fmt.Errorf("upstream %q: %w", raw, err)
		}
		return Spec{Raw: raw, Transport: Plain, Addr: addr}, nil
	}

	u, err := url.Parse(s)
	if err != nil {
		return Spec{}, fmt.Errorf("upstream %q: %w", raw, err)
	}
	spec := Spec{Raw: raw, ServerName: u.Fragment}
	var defPort string
	switch u.Scheme {
	case "udp":
		spec.Transport, defPort = Plain, "53"
	case "tls":
		spec.Transport, defPort = DoT, "853"
	case "https":
		spec.Transport, defPort = DoH, "443"
	default:
		return Spec{}, fmt.Errorf(
			"upstream %q: unknown scheme %q, want udp://, tls://, or https://", raw, u.Scheme)
	}
	if spec.Addr, err = hostPort(u.Host, defPort); err != nil {
		return Spec{}, fmt.Errorf("upstream %q: %w", raw, err)
	}
	if spec.Transport == DoH {
		path := u.Path
		if path == "" {
			path = "/dns-query"
		}
		spec.URL = "https://" + dohAuthority(spec) + path
	}
	return spec, nil
}

// ParseAll parses a whole configured list, failing on the first bad entry so a
// typo never starts a half-configured server.
func ParseAll(raws []string) ([]Spec, error) {
	specs := make([]Spec, 0, len(raws))
	for _, r := range raws {
		s, err := Parse(r)
		if err != nil {
			return nil, err
		}
		specs = append(specs, s)
	}
	return specs, nil
}

// hostPort requires an IP address and returns it as "ip:port" with defPort
// filled in.
func hostPort(s, defPort string) (string, error) {
	host, port := s, defPort
	if h, p, err := net.SplitHostPort(s); err == nil {
		host, port = h, p
	}
	addr, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return "", errors.New(bootstrapHint)
	}
	if _, err := net.LookupPort("tcp", port); err != nil {
		return "", fmt.Errorf("bad port %q", port)
	}
	return net.JoinHostPort(addr.String(), port), nil
}

// dohAuthority is the authority for the request URL. The socket always goes to
// Spec.Addr; this only decides what the server is asked to be.
func dohAuthority(s Spec) string {
	host, port, err := net.SplitHostPort(s.Addr)
	if err != nil {
		return s.Addr
	}
	switch {
	case s.ServerName != "":
		host = s.ServerName
	case strings.Contains(host, ":"):
		host = "[" + host + "]"
	}
	if port == "443" {
		return host
	}
	return host + ":" + port
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/upstream/ -v`
Expected: PASS, all six tests.

- [ ] **Step 5: Commit**

```bash
gofmt -l internal/upstream/
go vet ./internal/upstream/
git add internal/upstream/parse.go internal/upstream/parse_test.go
git commit -m "Parse upstreams by URL scheme

The scheme is the security policy. The host must be an IP address, since
a hostname would need DNS to bootstrap DNS."
```

---

## Task 2: The Upstream interface and the plaintext transport

**Files:**
- Create: `internal/upstream/upstream.go`, `internal/upstream/plain.go`
- Test: `internal/upstream/plain_test.go`

**Interfaces:**
- Consumes: `Spec`, `Parse`, `ParseAll`, `Transport` from Task 1.
- Produces:
  - `type Upstream interface { Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error); Secure() bool; String() string }`
  - `func New(s Spec, timeout time.Duration) (Upstream, error)`
  - `func NewAll(raws []string, timeout time.Duration) ([]Upstream, error)`

- [ ] **Step 1: Write the failing test**

Create `internal/upstream/plain_test.go`:

```go
package upstream

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// query is the request every transport test sends.
func query() *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion("a.example.com.", dns.TypeA)
	return m
}

// answer is the reply every transport test expects back.
func answer(req *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(req)
	rr, err := dns.NewRR("a.example.com. 300 IN A 203.0.113.7")
	if err != nil {
		panic(err)
	}
	m.Answer = []dns.RR{rr}
	return m
}

func wantAnswer(t *testing.T, resp *dns.Msg, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("Answer = %v, want one record", resp.Answer)
	}
	if a, ok := resp.Answer[0].(*dns.A); !ok || a.A.String() != "203.0.113.7" {
		t.Fatalf("Answer[0] = %v, want 203.0.113.7", resp.Answer[0])
	}
}

// plainServer starts UDP and TCP DNS listeners on one address. Both are needed
// because the truncation retry crosses from one to the other.
func plainServer(t *testing.T, udpHandler, tcpHandler dns.HandlerFunc) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenPacket("udp", l.Addr().String())
	if err != nil {
		l.Close()
		t.Fatal(err)
	}
	udp := &dns.Server{PacketConn: pc, Handler: udpHandler}
	tcp := &dns.Server{Listener: l, Handler: tcpHandler}
	go udp.ActivateAndServe()
	go tcp.ActivateAndServe()
	t.Cleanup(func() { udp.Shutdown(); tcp.Shutdown() })
	return l.Addr().String()
}

func TestPlainRoundTrip(t *testing.T) {
	addr := plainServer(t,
		func(w dns.ResponseWriter, r *dns.Msg) { w.WriteMsg(answer(r)) },
		func(w dns.ResponseWriter, r *dns.Msg) { w.WriteMsg(answer(r)) })

	u, err := New(Spec{Raw: addr, Transport: Plain, Addr: addr}, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if u.Secure() {
		t.Error("Secure() = true for plaintext; an answer over UDP cannot be authenticated")
	}
	if u.String() != addr {
		t.Errorf("String() = %q, want %q", u.String(), addr)
	}
	resp, err := u.Exchange(context.Background(), query())
	wantAnswer(t, resp, err)
}

// A truncated UDP reply must be retried over TCP.
func TestPlainRetriesTruncatedOverTCP(t *testing.T) {
	tcpCalls := 0
	addr := plainServer(t,
		func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(r)
			m.Truncated = true
			w.WriteMsg(m)
		},
		func(w dns.ResponseWriter, r *dns.Msg) {
			tcpCalls++
			w.WriteMsg(answer(r))
		})

	u, _ := New(Spec{Raw: addr, Transport: Plain, Addr: addr}, 2*time.Second)
	resp, err := u.Exchange(context.Background(), query())
	wantAnswer(t, resp, err)
	if tcpCalls != 1 {
		t.Errorf("TCP calls = %d, want 1", tcpCalls)
	}
}

func TestNewAll(t *testing.T) {
	ups, err := NewAll([]string{"udp://192.168.1.1:53", "1.1.1.1:53"}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(ups) != 2 {
		t.Fatalf("NewAll() returned %d upstreams, want 2", len(ups))
	}
	for _, u := range ups {
		if u.Secure() {
			t.Errorf("%s.Secure() = true, want false", u)
		}
	}
	if _, err := NewAll([]string{"nope://x"}, time.Second); err == nil {
		t.Error("NewAll() error = nil with a bad entry")
	}
}

func TestNewRejectsUnbuildableTransport(t *testing.T) {
	_, err := New(Spec{Raw: "x", Transport: Transport(99)}, time.Second)
	if err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Errorf("New() error = %v, want an unsupported-transport rejection", err)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/upstream/ -run 'TestPlain|TestNew'`
Expected: FAIL — `undefined: New`, `undefined: NewAll`.

- [ ] **Step 3: Write the implementation**

Create `internal/upstream/upstream.go`:

```go
package upstream

import (
	"context"
	"fmt"
	"time"

	"github.com/miekg/dns"
)

// Upstream is one configured resolver.
type Upstream interface {
	Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error)

	// Secure reports whether the channel is authenticated and encrypted.
	// Only a secure upstream's AD bit may reach a client.
	Secure() bool

	// String is the spec as configured, for logs and the UI.
	String() string
}

// New builds the resolver a Spec describes.
func New(s Spec, timeout time.Duration) (Upstream, error) {
	switch s.Transport {
	case Plain:
		return &plain{spec: s, timeout: timeout}, nil
	}
	return nil, fmt.Errorf("upstream %q: unsupported transport %s", s.Raw, s.Transport)
}

// NewAll parses and builds a whole configured list.
func NewAll(raws []string, timeout time.Duration) ([]Upstream, error) {
	specs, err := ParseAll(raws)
	if err != nil {
		return nil, err
	}
	ups := make([]Upstream, 0, len(specs))
	for _, s := range specs {
		u, err := New(s, timeout)
		if err != nil {
			return nil, err
		}
		ups = append(ups, u)
	}
	return ups, nil
}
```

Create `internal/upstream/plain.go`:

```go
package upstream

import (
	"context"
	"time"

	"github.com/miekg/dns"
)

// plain is UDP with a TCP retry on truncation: DNS as it has always been on the
// wire, and the only transport whose answers cannot be authenticated.
type plain struct {
	spec    Spec
	timeout time.Duration
}

func (p *plain) Secure() bool   { return false }
func (p *plain) String() string { return p.spec.Raw }

func (p *plain) Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	udp := &dns.Client{Net: "udp", Timeout: p.timeout}
	resp, _, err := udp.ExchangeContext(ctx, m, p.spec.Addr)
	if err != nil {
		return nil, err
	}
	if resp.Truncated {
		tcp := &dns.Client{Net: "tcp", Timeout: p.timeout}
		resp, _, err = tcp.ExchangeContext(ctx, m, p.spec.Addr)
		if err != nil {
			return nil, err
		}
	}
	return resp, nil
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/upstream/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
gofmt -l internal/upstream/
go vet ./internal/upstream/
git add internal/upstream/upstream.go internal/upstream/plain.go internal/upstream/plain_test.go
git commit -m "Add the Upstream interface and the plaintext transport

Secure() is the seam the AD policy hangs off: only an authenticated,
encrypted channel may carry a verdict through to a client."
```

---

## Task 3: DNS-over-TLS with connection pooling

**Files:**
- Create: `internal/upstream/pool.go`, `internal/upstream/dot.go`, `internal/upstream/testhelp_test.go`
- Modify: `internal/upstream/upstream.go` — add the `DoT` case to `New`
- Test: `internal/upstream/dot_test.go`

**Interfaces:**
- Consumes: `Upstream`, `New`, `Spec` from Tasks 1–2; test helpers `query`, `answer`, `wantAnswer` from `plain_test.go`.
- Produces:
  - `func tlsConfig(s Spec) *tls.Config` — used by both `dot.go` and `doh.go`
  - `func testCert(t *testing.T, names ...string) (tls.Certificate, *x509.CertPool)` — used by both transport test files

- [ ] **Step 1: Write the shared test helpers**

Create `internal/upstream/testhelp_test.go`:

```go
package upstream

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

// testCert makes a self-signed certificate valid for 127.0.0.1 and ::1 plus any
// extra names, and a pool that trusts it. Nothing in production may bypass
// verification, so tests supply their own root instead of turning it off.
func testCert(t *testing.T, names ...string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "kydns test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:              names,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}
```

- [ ] **Step 2: Write the failing test**

Create `internal/upstream/dot_test.go`:

```go
package upstream

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// dotServer starts an in-process DNS-over-TLS server. handshakes counts TLS
// handshakes, which is how the reuse test proves the pool is doing its job.
func dotServer(t *testing.T, cert tls.Certificate, idle time.Duration, h dns.HandlerFunc) (addr string, handshakes *atomic.Int64) {
	t.Helper()
	handshakes = new(atomic.Int64)
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			handshakes.Add(1)
			return nil, nil
		},
	}
	l, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{Listener: l, Net: "tcp-tls", Handler: h}
	if idle > 0 {
		srv.IdleTimeout = func() time.Duration { return idle }
	}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })
	return l.Addr().String(), handshakes
}

func dotSpec(addr string, pool *x509.CertPool) Spec {
	return Spec{Raw: "tls://" + addr, Transport: DoT, Addr: addr, RootCAs: pool}
}

func TestDoTRoundTrip(t *testing.T) {
	cert, pool := testCert(t)
	addr, _ := dotServer(t, cert, 0, func(w dns.ResponseWriter, r *dns.Msg) { w.WriteMsg(answer(r)) })

	u, err := New(dotSpec(addr, pool), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !u.Secure() {
		t.Error("Secure() = false for DoT")
	}
	resp, err := u.Exchange(context.Background(), query())
	wantAnswer(t, resp, err)
}

// A certificate signed by an unknown authority must fail. There is no option
// anywhere to accept it.
func TestDoTRejectsUntrustedCertificate(t *testing.T) {
	cert, _ := testCert(t)
	addr, _ := dotServer(t, cert, 0, func(w dns.ResponseWriter, r *dns.Msg) { w.WriteMsg(answer(r)) })

	other := x509.NewCertPool() // trusts nothing the server can present
	u, _ := New(dotSpec(addr, other), 2*time.Second)
	if _, err := u.Exchange(context.Background(), query()); err == nil {
		t.Fatal("Exchange() error = nil against an untrusted certificate")
	} else if !strings.Contains(err.Error(), "certificate") {
		t.Errorf("error = %v, want it to name the certificate", err)
	}
}

// The pool exists so a cache miss does not cost a TLS handshake.
func TestDoTReusesConnections(t *testing.T) {
	cert, pool := testCert(t)
	addr, handshakes := dotServer(t, cert, 0, func(w dns.ResponseWriter, r *dns.Msg) { w.WriteMsg(answer(r)) })

	u, _ := New(dotSpec(addr, pool), 2*time.Second)
	for i := 0; i < 5; i++ {
		resp, err := u.Exchange(context.Background(), query())
		wantAnswer(t, resp, err)
	}
	if got := handshakes.Load(); got != 1 {
		t.Errorf("TLS handshakes = %d, want 1 reused connection", got)
	}
}

// A pooled connection the server has since closed must be retried once.
func TestDoTRetriesAfterServerClosesIdleConnection(t *testing.T) {
	cert, pool := testCert(t)
	addr, handshakes := dotServer(t, cert, time.Millisecond,
		func(w dns.ResponseWriter, r *dns.Msg) { w.WriteMsg(answer(r)) })

	u, _ := New(dotSpec(addr, pool), 2*time.Second)
	resp, err := u.Exchange(context.Background(), query())
	wantAnswer(t, resp, err)

	time.Sleep(50 * time.Millisecond) // let the server drop the idle connection

	resp, err = u.Exchange(context.Background(), query())
	wantAnswer(t, resp, err)
	if got := handshakes.Load(); got != 2 {
		t.Errorf("TLS handshakes = %d, want 2 (the dead connection redialled once)", got)
	}
}

// A connection that was never pooled gets no retry, or a dead upstream loops.
func TestDoTDoesNotRetryAFreshConnection(t *testing.T) {
	cert, pool := testCert(t)
	addr, _ := dotServer(t, cert, 0, func(w dns.ResponseWriter, r *dns.Msg) {
		w.Close() // hang up without replying
	})

	u, _ := New(dotSpec(addr, pool), 500*time.Millisecond)
	done := make(chan error, 1)
	go func() {
		_, err := u.Exchange(context.Background(), query())
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Exchange() error = nil against a server that hangs up")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Exchange() never returned: the retry is looping")
	}
}

func TestPoolExpiresIdleConnections(t *testing.T) {
	cert, pool := testCert(t)
	addr, handshakes := dotServer(t, cert, 0, func(w dns.ResponseWriter, r *dns.Msg) { w.WriteMsg(answer(r)) })

	d := newDoT(dotSpec(addr, pool), 2*time.Second)
	d.pool.ttl = 0 // every returned connection is already stale
	for i := 0; i < 3; i++ {
		resp, err := d.Exchange(context.Background(), query())
		wantAnswer(t, resp, err)
	}
	if got := handshakes.Load(); got != 3 {
		t.Errorf("TLS handshakes = %d, want 3 with expiry forced on", got)
	}
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `go test ./internal/upstream/ -run TestDoT`
Expected: FAIL — `undefined: newDoT`, and `New` returns "unsupported transport DoT".

- [ ] **Step 4: Write the pool**

Create `internal/upstream/pool.go`:

```go
package upstream

import (
	"context"
	"time"

	"github.com/miekg/dns"
)

// pool keeps a few idle TLS connections alive. dns.Client dials a fresh
// connection per Exchange, which costs a full TLS handshake — two extra round
// trips to the upstream on every cache miss.
type pool struct {
	idle chan *pooledConn
	dial func(context.Context) (*dns.Conn, error)
	ttl  time.Duration
	now  func() time.Time
}

type pooledConn struct {
	c       *dns.Conn
	expires time.Time
}

func newPool(size int, ttl time.Duration, dial func(context.Context) (*dns.Conn, error)) *pool {
	return &pool{idle: make(chan *pooledConn, size), dial: dial, ttl: ttl, now: time.Now}
}

// get returns an idle connection or dials a new one. reused reports which,
// because only a reused connection is worth retrying after a failure.
func (p *pool) get(ctx context.Context) (conn *dns.Conn, reused bool, err error) {
	for {
		select {
		case pc := <-p.idle:
			if p.now().Before(pc.expires) {
				return pc.c, true, nil
			}
			pc.c.Close()
		default:
			c, err := p.dial(ctx)
			return c, false, err
		}
	}
}

func (p *pool) put(c *dns.Conn) {
	select {
	case p.idle <- &pooledConn{c: c, expires: p.now().Add(p.ttl)}:
	default:
		c.Close()
	}
}
```

- [ ] **Step 5: Write the DoT transport**

Create `internal/upstream/dot.go`:

```go
package upstream

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

// dotIdle is how long a spare connection is worth keeping. RFC 7858 servers
// commonly drop idle connections after about ten seconds.
const dotIdle = 10 * time.Second

// dotIdleConns is deliberately small: a household's query rate is low, and each
// spare connection is a socket held open at the provider.
const dotIdleConns = 2

type dot struct {
	spec    Spec
	timeout time.Duration
	pool    *pool
}

func newDoT(s Spec, timeout time.Duration) *dot {
	client := &dns.Client{Net: "tcp-tls", Timeout: timeout, TLSConfig: tlsConfig(s)}
	return &dot{
		spec:    s,
		timeout: timeout,
		pool: newPool(dotIdleConns, dotIdle, func(ctx context.Context) (*dns.Conn, error) {
			return client.DialContext(ctx, s.Addr)
		}),
	}
}

func (d *dot) Secure() bool   { return true }
func (d *dot) String() string { return d.spec.Raw }

// Exchange retries once on a reused connection, because the server may have
// closed it while it sat idle. A fresh connection that fails is a real failure.
func (d *dot) Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	for {
		conn, reused, err := d.pool.get(ctx)
		if err != nil {
			return nil, err
		}
		resp, err := d.roundTrip(ctx, conn, m)
		if err == nil {
			d.pool.put(conn)
			return resp, nil
		}
		conn.Close()
		if !reused {
			return nil, err
		}
	}
}

func (d *dot) roundTrip(ctx context.Context, conn *dns.Conn, m *dns.Msg) (*dns.Msg, error) {
	deadline := time.Now().Add(d.timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if err := conn.WriteMsg(m); err != nil {
		return nil, err
	}
	resp, err := conn.ReadMsg()
	if err != nil {
		return nil, err
	}
	// One query per connection at a time, so a mismatched id is not a
	// pipelined reply — it is the wrong answer.
	if resp.Id != m.Id {
		return nil, fmt.Errorf("upstream %s: reply id %d does not match query %d", d.spec.Raw, resp.Id, m.Id)
	}
	return resp, nil
}

// tlsConfig verifies the peer against ServerName when one was configured, and
// against the dialled IP otherwise. There is deliberately no way to skip it.
func tlsConfig(s Spec) *tls.Config {
	name := s.ServerName
	if name == "" {
		if host, _, err := net.SplitHostPort(s.Addr); err == nil {
			name = host
		}
	}
	return &tls.Config{ServerName: name, RootCAs: s.RootCAs, MinVersion: tls.VersionTLS12}
}
```

- [ ] **Step 6: Add the DoT case to New**

In `internal/upstream/upstream.go`, extend the switch:

```go
	switch s.Transport {
	case Plain:
		return &plain{spec: s, timeout: timeout}, nil
	case DoT:
		return newDoT(s, timeout), nil
	}
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `go test ./internal/upstream/ -race -v`
Expected: PASS, including all six DoT tests.

- [ ] **Step 8: Commit**

```bash
gofmt -l internal/upstream/
go vet ./internal/upstream/
git add internal/upstream/pool.go internal/upstream/dot.go \
        internal/upstream/dot_test.go internal/upstream/testhelp_test.go \
        internal/upstream/upstream.go
git commit -m "Add DNS-over-TLS over a pooled connection

dns.Client handshakes per Exchange, which would put two extra round trips
on every cache miss. A reused connection the server has since closed is
redialled once; a fresh one that fails is a real failure."
```

---

## Task 4: DNS-over-HTTPS

**Files:**
- Create: `internal/upstream/doh.go`
- Modify: `internal/upstream/upstream.go` — add the `DoH` case to `New`
- Test: `internal/upstream/doh_test.go`

**Interfaces:**
- Consumes: `Upstream`, `New`, `Spec`, `tlsConfig` from Tasks 1–3; `testCert`, `query`, `answer`, `wantAnswer` from the test helpers.
- Produces: nothing new beyond the `DoH` case.

- [ ] **Step 1: Write the failing test**

Create `internal/upstream/doh_test.go`:

```go
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
	srv := dohServer(t, cert, dohEcho(t, seen))

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
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/upstream/ -run TestDoH`
Expected: FAIL — `New` returns "unsupported transport DoH".

- [ ] **Step 3: Write the implementation**

Create `internal/upstream/doh.go`:

```go
package upstream

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const dohMediaType = "application/dns-message"

// doh speaks RFC 8484. net/http pools connections, so unlike DoT there is
// nothing to keep alive by hand.
type doh struct {
	spec   Spec
	client *http.Client
}

func newDoH(s Spec, timeout time.Duration) *doh {
	dialer := &net.Dialer{Timeout: timeout}
	return &doh{
		spec: s,
		client: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig(s),
				// The URL carries the server name; the socket always goes to
				// the configured IP, so no hostname needs resolving.
				DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
					return dialer.DialContext(ctx, network, s.Addr)
				},
				ForceAttemptHTTP2: true,
				IdleConnTimeout:   30 * time.Second,
			},
		},
	}
}

func (d *doh) Secure() bool   { return true }
func (d *doh) String() string { return d.spec.Raw }

func (d *doh) Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	q := m.Copy()
	q.Id = 0 // RFC 8484 section 4.1
	wire, err := q.Pack()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.spec.URL, bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", dohMediaType)
	req.Header.Set("Accept", dohMediaType)

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("upstream %s: HTTP %s", d.spec.Raw, resp.Status)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, dohMediaType) {
		return nil, fmt.Errorf("upstream %s: content type %q, want %s", d.spec.Raw, ct, dohMediaType)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, dns.MaxMsgSize))
	if err != nil {
		return nil, err
	}
	out := new(dns.Msg)
	if err := out.Unpack(body); err != nil {
		return nil, fmt.Errorf("upstream %s: %w", d.spec.Raw, err)
	}
	out.Id = m.Id
	return out, nil
}
```

- [ ] **Step 4: Add the DoH case to New**

In `internal/upstream/upstream.go`:

```go
	case DoH:
		return newDoH(s, timeout), nil
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./internal/upstream/ -race -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
gofmt -l internal/upstream/
go vet ./internal/upstream/
git add internal/upstream/doh.go internal/upstream/doh_test.go internal/upstream/upstream.go
git commit -m "Add DNS-over-HTTPS

net/http pools connections already, so the whole transport is one POST.
The dialer is pinned to the configured IP while the URL carries the
server name."
```

---

Tasks 5 through 9 are in
[part 2](2026-08-14-kydns-encrypted-upstreams-part2.md): plumbing the `DO` bit,
the transport-aware forwarder and its `AD` policy, configuration, the web
surface, and documentation.
