# KyDNS Encrypted Upstreams (DoT and DoH)

Date: 2026-08-14
Status: Approved, ready for implementation planning

## Scope

KyDNS forwards non-authoritative queries over plain UDP today. Anything on the
path between KyDNS and `1.1.1.1` can read every name the household looks up and
can forge any answer it likes. This spec closes the path.

**KyDNS does not become a validating resolver.** It does not hold a root trust
anchor, does not walk a chain of trust, and does not verify an RRSIG. It secures
the channel to a resolver that already does all of that, and passes that
resolver's verdict through to the client. Local DNSSEC validation is a separate,
much larger piece of work and is explicitly out of scope. `miekg/dns` supplies
`RRSIG.Verify` and NSEC3 hashing but no chain walking, trust-anchor management,
or denial-of-existence proofs, so that work would be built from scratch.

Also out of scope: signing the private zone, DNSSEC for authoritative answers,
per-view upstreams, and upstream health probing beyond recording what the last
query did.

### Decisions

| Decision | Choice |
|---|---|
| Threat closed | Network path to the upstream: eavesdropping and forgery |
| Validation | Delegated to the upstream; KyDNS trusts its `AD` bit |
| Transports | DoT (RFC 7858) and DoH (RFC 8484), plus existing plaintext |
| Selection | URL scheme per upstream — the scheme is the policy |
| Failure policy | Strict by construction; the escape hatch is a `udp://` entry |
| Upstream host | Must be an IP address; `#servername` when the certificate needs a name |
| Certificate verification | Always on. No `insecure_skip_verify`, now or later |
| `CD` toward upstream | Always 0 — a client cannot ask KyDNS to skip upstream validation |
| `AD` toward client | Only from a secure channel; cleared at the source otherwise |
| Defaults | `tls://1.1.1.1:853`, `tls://9.9.9.9:853` |

## Part 1 — Configuration

### The scheme is the policy

```yaml
dns:
  upstreams:
    - tls://1.1.1.1:853
    - https://9.9.9.9/dns-query
    - udp://192.168.1.1:53          # explicit plaintext, opted into per upstream
```

| Form | Transport | Default port | Default path |
|---|---|---|---|
| `tls://IP[:port]` | DoT | 853 | — |
| `https://IP[:port][/path]` | DoH, POST | 443 | `/dns-query` |
| `udp://IP[:port]` | plaintext UDP, TCP on truncation | 53 | — |
| `IP:port` | plaintext | — | backward compatible |

There is no separate "require encryption" boolean. A list containing only
`tls://` and `https://` entries is strict: every failure is a transport failure,
failover runs to the end of the list, and the query returns `SERVFAIL`. The
escape hatch is adding one `udp://` line — explicit, per upstream, and visible
in the file that caused it. Nothing to configure and nothing to forget.

### The host must be an IP address

A hostname upstream needs DNS to bootstrap DNS. On a machine whose own resolver
is KyDNS, that is a loop, and in Docker it silently depends on whatever the
container's `resolv.conf` points at. The loader rejects hostnames:

```
dns.upstreams "tls://dns.quad9.net:853": host must be an IP address —
DNS cannot bootstrap DNS. Use the provider's IP, and add #dns.quad9.net if
its certificate needs a hostname.
```

Cloudflare, Quad9 and Google all carry IP SANs on their DoT and DoH
certificates, so the common cases need nothing further. When a certificate needs
a name, the URL fragment supplies it:

```yaml
    - tls://45.90.28.0:853#abc123.dns.nextdns.io
```

The fragment sets the TLS SNI, the name the certificate is verified against, and
for DoH the request URL and `Host` header — while the connection still dials the
pinned IP. Fragments are never sent over the wire by HTTP, so this is free.

### Certificate verification

Always on, against the system root pool. There is no option to disable it and
none will be added. A certificate that does not verify fails that upstream, and
the failure surfaces in the UI (Part 5).

### Defaults change

`dns.upstreams` defaults to `tls://1.1.1.1:853`, `tls://9.9.9.9:853`. On a
network that blocks outbound 853 this turns a working install into `SERVFAIL`,
which is the intended behaviour: the UI says which upstream failed and why, and
the fix is one documented line. Nothing is deployed against the old default
today, so the change costs nothing now.

## Part 2 — The `AD` bit

### Toward the upstream

- `CD = 0`, always. KyDNS never lets a client disable upstream validation. A
  client that sets `CD=1` receives a validated answer instead of an unvalidated
  one — strictly safer than what it asked for, at the cost of not being able to
  fetch bogus data for its own inspection.
- `AD = 1`, always. Under RFC 6840 §5.7 a validating resolver sets `AD` on its
  response when the query carried `DO` or `AD`. Requesting it via `AD` rather
  than `DO` gets the verdict without the RRSIG payload.
- The client's `DO` bit is forwarded exactly as sent, so a validating stub still
  receives the records it needs.

### Toward the client

One line in the forwarder, applied the moment a response comes back, enforces
the whole property:

```go
if !u.Secure() {
	resp.AuthenticatedData = false
}
```

Doing it at the source rather than at the response boundary means an answer from
a plaintext channel can never carry `AD` — not to the client, not into the
cache, and not on a later cache hit. No downstream code has to remember.

Authoritative answers are unsigned local data. `Authoritative.Answer` builds a
fresh message, so `AD` is already false, and `SetRcode` does not copy it from
the request. This gets an explicit test rather than being left to hold by
accident.

## Part 3 — Cache

`cacheKey` gains the `DO` bit:

```go
type cacheKey struct {
	name  string
	qtype uint16
	do    bool
}
```

Without it a `DO=1` client and a `DO=0` client share an entry and one of them
gets a response shaped for the other: the plain client receives RRSIGs it did
not ask for, or — worse — the validating stub receives a stripped answer and
concludes the zone is bogus. `Get` and `Put` take `do`, and the forwarder's
singleflight key includes it for the same reason.

## Part 4 — Code shape

### A new `internal/upstream` package

`Exchanger`'s `addr string` parameter stops fitting once an upstream carries a
transport, a TLS configuration and a URL. It is replaced by:

```go
// Upstream is one configured resolver.
type Upstream interface {
	Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error)
	Secure() bool   // channel is authenticated and encrypted
	String() string // the spec as configured, for logs and the UI
}
```

The package holds parsing and all three implementations. `config` calls
`upstream.Parse` for validation and `dnsserver` consumes the interface, so
neither depends on the other and the accepted grammar is defined once.

```
internal/upstream/
  parse.go   Spec, Transport, Parse
  plain.go   UDP with TCP retry on truncation — today's UDPExchanger
  dot.go     DoT over a pooled TLS connection
  doh.go     DoH over net/http
  pool.go    the DoT idle-connection free list
```

```go
type Spec struct {
	Raw        string    // as configured, for logs and the UI
	Transport  Transport // Plain, DoT, DoH
	Addr       string    // "IP:port" — always what gets dialed
	ServerName string    // SNI and verified name; empty verifies against the IP
	URL        string    // DoH only
	RootCAs    *x509.CertPool // nil means system roots; set by tests
}
```

`dnsserver.Exchanger` and `dnsserver.UDPExchanger` are deleted. The forwarder
holds `[]upstream.Upstream`, and `fakeExchanger` in the existing tests becomes a
`fakeUpstream`.

### DoT needs a connection pool

`dns.Client{Net: "tcp-tls"}` performs a full TLS handshake per `Exchange` — two
extra round trips to Cloudflare on every cache miss. `pool` is a buffered
channel of idle connections, each stamped with a deadline:

- `get` drains expired connections, then takes one or dials.
- `put` returns the connection if there is room, and closes it otherwise.
- Idle TTL 10s, at most 2 idle connections.

A connection taken from the pool may have been closed by the server in the
meantime. On a write or read error with a *pooled* connection, close it and
retry once on a fresh dial; on a freshly dialled connection, fail. That
distinction is what stops the retry from looping.

Each connection carries exactly one outstanding query, so replies need no
pipelining logic — a reply whose ID does not match the request is discarded and
the exchange fails. Read and write deadlines come from the context.

### DoH is the smaller of the two

`net/http` pools connections already. A `Transport` with `DialContext` pinned to
`Spec.Addr` lets the request URL carry the server name while the socket goes to
the configured IP.

- POST, `Content-Type` and `Accept` of `application/dns-message`.
- Message ID zeroed on the wire per RFC 8484 §4.1, restored on the response.
- Non-200 is an error carrying the status; so is a wrong content type.
- The body is read through `io.LimitReader` capped at `dns.MaxMsgSize`.

### Forwarder and server

```go
func NewForwarder(ups []upstream.Upstream, timeout time.Duration, c *Cache) *Forwarder
func (f *Forwarder) Resolve(ctx context.Context, q dns.Question, do bool) (*dns.Msg, error)
```

`ServeDNS` reads `DO` off the request's OPT record and passes it down. It also
strips the OPT record from the response when the client did not send one — the
forwarder always speaks EDNS0 upstream, and returning an OPT to a client that
did not offer one is a protocol violation that only became reachable once `DO`
started varying.

## Part 5 — Loud failure

The same shape as `allow_tailscale`: closed by default, unmistakable when it
bites, one line to change once you understand what you are changing.

- **Startup** logs a warning per plaintext upstream: *"upstream 192.168.1.1:53
  is unencrypted; answers from it cannot be authenticated."*
- **Dashboard** shows a banner whenever any upstream is plaintext.
- **Settings** lists every upstream with its transport, a plaintext flag, and
  its last error with a timestamp.

The last error is the part that makes strict mode survivable. Without it, a
firewall that blocks 853 presents as "the internet is broken." With it, the
Settings page says `tls://1.1.1.1:853 — dial tcp 1.1.1.1:853: i/o timeout`, and
the operator knows within seconds both what happened and what to do.

```go
type Status struct {
	Spec      string
	Secure    bool
	LastError string
	LastErrAt time.Time
	LastOKAt  time.Time
}

func (f *Forwarder) Status() []Status
```

Recorded under a mutex on each exchange attempt. `middleware.Options.Upstreams`
changes from `[]string` to `[]Status`, and the dashboard and settings templates
render the extra columns.

## Part 6 — Tests

Parsing:

- Every scheme, with and without explicit port and path.
- `#servername` populates SNI, the verified name, and the DoH URL host.
- A hostname host is rejected with the bootstrap message.
- Bare `IP:port` still parses as plaintext.
- Unknown schemes are rejected and the error names the accepted ones.

Transport, hermetic — an in-process DoT server and an `httptest` DoH server,
each with a self-signed certificate carrying a `127.0.0.1` IP SAN, injected
through `Spec.RootCAs`:

- A round trip over each transport returns the expected answer.
- A certificate signed by an unknown CA fails, and the error says so.
- A DoT connection closed by the server between queries is retried once and
  succeeds; a fresh connection that fails is not retried.
- DoH: non-200, wrong content type, and an oversized body each fail.
- DoH zeroes the wire ID and restores the original.

Policy:

- A plaintext upstream that sets `AD` yields a response with `AD` cleared.
- A secure upstream that sets `AD` yields a response with `AD` preserved.
- An authoritative answer never carries `AD`.
- Outbound queries always have `CD=0` and `AD=1`.
- The client's `DO` is forwarded, and a client that sent no OPT gets none back.
- `DO=1` and `DO=0` for the same name do not share a cache entry.
- An all-encrypted upstream list, all failing, returns `SERVFAIL`.
- A failing `tls://` followed by a working `udp://` succeeds — the escape hatch
  works — and the answer has `AD` cleared.
- `Status()` reports the last error per upstream, and Settings renders it.

CI gains one network-dependent step: the container resolves a public name over
DoT end to end. It is the only check in the suite that needs the internet, and
it is worth having — everything else proves the code is correct against a fake,
and this proves it is correct against Cloudflare.

## Part 7 — Documentation

- `kydns.example.yaml` ships `tls://` upstreams and a commented `udp://` line
  explaining what adding it gives up. The existing example guard tests keep it
  matching the code defaults.
- README's settings table gains the upstream grammar; the "Not yet" list gains
  *"Local DNSSEC validation. KyDNS trusts the upstream's verdict over an
  encrypted channel; it does not verify signatures itself,"* and loses the
  DoT/DoH line.
- A short README section on the failure mode: what `SERVFAIL` with an all-`tls`
  list means, where to see the reason, and what adding a `udp://` upstream costs
  you.
