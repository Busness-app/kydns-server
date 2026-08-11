# KyDNS v1 Design

Date: 2026-08-11
Status: Approved, ready for implementation planning

## Scope

KyDNS v1 is a single-node, self-hosted local DNS server and private service
directory. It answers authoritative queries for a private domain, forwards
everything else, discovers DHCP leases, checks service health, and exposes an
authenticated admin API, web UI, and CLI.

**Replication is out of scope for v1** and gets its own spec. `DESGINE.md`
lists it in the initial implementation boundary; that boundary is deliberately
narrowed here because replication roughly doubles the v1 surface area and is the
part least needed to make KyDNS useful. The design keeps a single write
chokepoint so the change log can be added later without restructuring.

Also out of scope, consistent with `DESGINE.md`: ad blocking, parental controls,
device posture, traffic inspection, automatic peer discovery. Additionally
deferred from the `README.md` capability list: Docker Compose discovery, split
views (home/VPN/guest/lab), optional local TLS certificate issuance, and
Pi-hole/AdGuard filter-list integration.

### Decisions

| Decision | Choice |
|---|---|
| v1 scope | Single node; replication deferred |
| DNS engine | Go with `github.com/miekg/dns`, own server |
| Storage | SQLite via `modernc.org/sqlite` (pure Go, no cgo) |
| Admin UI | Server-rendered Go templates, `go:embed` |
| Auth | Single admin account plus API tokens |
| Extra v1 features | Health checks with status in the UI; DHCP lease discovery |
| DHCP source | dnsmasq lease file as the reference adapter |

## Part 1 — Shape and data

### Process and CLI

One binary, one process. `kydns` with subcommands:

- `serve` — the daemon
- `service`, `record`, `token`, `export`, `import` — admin operations

The CLI talks to the running server over the admin HTTP API using a token. It
never opens the database directly. This keeps a single writer and makes `kydns`
work against a remote server for free.

One deliberate exception: `kydns admin reset-password` opens the database file
directly for lockout recovery. It requires local filesystem access and is the
only command that bypasses the API.

### Packages

All under `internal/`:

| Package | Responsibility |
|---|---|
| `config` | Process config, a YAML file: bind addresses, private domain, reverse zones, upstreams, data dir, lease file, TTLs, intervals. Loaded before anything else. The DNS listener defaults to `:53` on UDP and TCP. |
| `store` | SQLite access and migrations. Every write goes through here — the one chokepoint where the replication change log later hooks in. |
| `registry` | Domain model, validation, and the application service both transports call. Services, aliases, records, precedence. Knows nothing about DNS wire format or HTTP. |
| `zone` | Builds an immutable snapshot (forward index, reverse index) from the registry. |
| `dnsserver` | `miekg/dns` handlers: authoritative answers, forwarder, cache. |
| `adminapi` | JSON API and auth middleware. |
| `web` | Templates and static assets via `go:embed`. |
| `discovery/dhcp` | Lease-source adapter; dnsmasq format as the reference implementation. |
| `health` | Service probes. |

### The snapshot

The DNS hot path never touches SQLite. `zone` builds an immutable snapshot held
in an `atomic.Pointer`. Any registry write rebuilds it and swaps the pointer;
DNS queries read it lock-free. At homelab scale a rebuild takes microseconds, so
this buys concurrency safety and a clean read model for the price of one atomic
swap.

### Persistence

Persisted in SQLite: services, aliases, records, the admin account (argon2id
hash), and API tokens (SHA-256 hashes).

Memory only: health status, DHCP-discovered leases, and the DNS cache. Leases
are re-read from the file on each poll; health repopulates within one interval
after restart. This keeps churny, self-healing data out of the database and out
of backups. A discovered lease becomes a database row only when explicitly
promoted to a service.

> **Deviation from `DESGINE.md`:** its "Local data" section requires the store
> to contain discovery results and health-check status. This design keeps both
> in memory. `DESGINE.md` is updated to match.

### Precedence

Enforced at snapshot build, and logged whenever it takes effect:

```
manual record  >  service/alias  >  discovered lease
```

### Validation

Applied in `registry` before anything reaches the store:

- RFC 1035 label rules and length limits.
- Authoritative names must fall inside the configured private domain.
- A CNAME may not coexist with A/AAAA at the same name.
- An alias may not collide with an existing name.
- No wildcards in v1.

### Export and import

`kydns export` emits YAML or JSON containing services, aliases, and records.
It never emits the password hash, token hashes, or upstream credentials.
`kydns import` takes `--merge` or `--replace`. This is the Git-based
configuration workflow from `README.md`.

## Part 2 — Query path, discovery, and health

### Pipeline

1. Parse the query. Non-`QUERY` opcodes get `NOTIMP`; non-`IN` classes get
   `REFUSED`.
2. Check the query ACL.
3. Look for an authoritative match in the snapshot.
4. Otherwise forward.

DNS clients are untrusted input (`SECURITY.md`). Nothing on this path can reach
the store.

### Access control

`allow_query` is a CIDR list defaulting to loopback plus RFC1918 and ULA ranges.
Everything else gets `REFUSED`. Default-closed, so a KyDNS accidentally exposed
on a WAN interface is not an open resolver.

### Authoritative answers

The server is authoritative for the configured private domain and for the
reverse zones named in config (for example `192.168.1.0/24`). Within them:

| Case | Response |
|---|---|
| Name and type match | Answer with `AA` set |
| Name exists, type does not | `NOERROR`, empty answer, SOA in authority |
| Name absent from the zone | `NXDOMAIN` with SOA in authority |
| CNAME with in-zone target | CNAME plus the chased A/AAAA in one answer, depth cap 8 |
| CNAME with out-of-zone target | CNAME alone; the client's resolver continues |

The apex `SOA` and a single `NS` (`ns.<domain>` plus glue A record) are
synthesized, not stored. **The SOA serial is the snapshot generation counter**,
which increments on every rebuild.

One configured TTL applies to all authoritative records, defaulting to 60
seconds because homelab addresses move.

### Reverse zones

PTRs are derived at snapshot build from forward records whose address falls
inside a configured reverse CIDR. They are not authored directly.

- The service's primary name wins.
- Aliases do not generate PTRs.
- A manual PTR record overrides the derived one.
- An `.arpa` query outside every configured reverse zone is forwarded, not
  answered `NXDOMAIN`.

### Forwarder

Sequential failover through the configured upstreams with a per-query timeout
of about 2 seconds. `SERVFAIL` only when every upstream fails. Plain UDP and TCP
in v1.

Truncated upstream replies are retried over TCP. The client's advertised EDNS0
buffer size is respected.

`ponytail:` no DoT or DoH in v1. Upgrade path: the upstream client is an
interface, so an encrypted transport is a new implementation plus config
parsing, with no change to the handler.

### Cache

Keyed on lowercased qname plus qtype, storing the response with TTLs decremented
by age on serve.

- Upstream TTLs clamped into a configured `[min, max]`.
- Negative answers cached per RFC 2308 using the SOA MINIMUM, clamped by a
  tighter configured maximum.
- Size-capped LRU with lazy expiry on lookup, plus a periodic sweep.
- Authoritative answers are never cached; they already live in memory.
- Identical concurrent misses collapse through single-flight. This matters for
  the boot-time stampede when every device on the LAN wakes at once.
- An admin endpoint flushes the cache.

### Query logging

Off by default, per `LOGGING.md`. When enabled it records qname, qtype, rcode,
source (authoritative, cache, or upstream), and duration. Logging the client IP
requires a second, separate flag.

### DHCP discovery

A `LeaseSource` interface returning leases of `{MAC, IP, Hostname, Expires}`,
with the dnsmasq lease file as the reference adapter. Polled every 30 seconds by
default, re-parsed when the file mtime changes.

Discovery sources are untrusted configuration input (`SECURITY.md`), so:

- Hostnames are lowercased; `*` and empty hostnames are skipped.
- Anything that is not a valid DNS label after lowercasing is skipped and
  logged, never silently rewritten.
- Expired leases are dropped at parse time.
- On duplicate hostnames, the newest lease wins and the conflict is logged.

Discovered names land flat in the private domain, protected by the precedence
rule. Every shadowed lease is logged. Leases are never persisted; the UI offers
**Promote to service** to make one durable.

### Health checks

Optional per service, `http(s)://` or `tcp://`.

| Setting | Default |
|---|---|
| Interval | 30s |
| Timeout | 5s |
| Failures to mark down | 2 consecutive |
| Successes to mark up | 1 |

Probes run in a bounded worker pool so a large registry does not spawn one
goroutine per service. `--check-insecure` skips TLS verification, because
private services usually carry self-signed certificates. For HTTP, a 2xx or 3xx
response is healthy and redirects are not followed. For `tcp://`, a completed
connection within the timeout is healthy; nothing is read or written.

**Health never affects DNS answers in v1.** There is no automatic record
withdrawal or failover. Status is informational, which keeps resolution
deterministic and debuggable.

Only status transitions are logged, not individual probes.

## Part 3 — Admin surface, auth, failure behavior, testing

### One service, two transports

`adminapi` (JSON) and `web` (HTML forms) are thin layers over the same
`registry` service calls. Validation lives in one place and the two transports
cannot drift apart.

### Auth

The admin listener is separate from the DNS listener and binds `127.0.0.1:8053`
by default, per `SECURITY.md`. TLS is normally terminated by the operator's
proxy; an optional built-in cert and key are supported.

| Concern | Design |
|---|---|
| First run | With no admin configured, a setup token is printed to stdout and `/setup` is the only reachable route until a password is set |
| Password | argon2id. Failed logins add an increasing per-source-IP delay before the next attempt is answered. There is no permanent lockout, which would let an attacker deny the operator access |
| Sessions | In-memory, `HttpOnly` and `SameSite=Lax` cookie, `Secure` when served over TLS, with a per-session CSRF token in every form. Restart forces re-login, which keeps session state out of the database |
| API tokens | `kydns_<random>`, stored as a SHA-256 hash, displayed once at creation, sent as a bearer token. High-entropy random tokens do not need a slow KDF, and argon2 on every API call would be costly |
| Lockout recovery | `kydns admin reset-password`, requiring local filesystem access |

### API

Under `/api/v1`:

- `GET`/`POST` `/services`; `GET`/`PATCH`/`DELETE` `/services/{id}`
- `POST` `/services/{id}/aliases`; `DELETE` `/services/{id}/aliases/{name}`
- `GET`/`POST` `/records`; `DELETE` `/records/{id}`
- `GET` `/leases`; `POST` `/leases/{ip}/promote`
- `GET` `/health` — per-service status
- `GET` `/stats` — cache and upstream counters
- `GET` `/export?format=yaml|json`; `POST` `/import?mode=merge|replace`
- `GET`/`POST`/`DELETE` `/tokens`
- `POST` `/cache/flush`
- `GET` `/healthz` — liveness, unauthenticated

Errors return JSON with a machine-readable code, a message, and the offending
field name, so the CLI and the UI render the same validation failure. Status
codes: 400 validation, 401 unauthenticated, 403 unauthorized, 404 missing,
409 name collision.

### Web UI

Five screens:

1. **Dashboard** — counts, upstream status, cache statistics, health summary.
2. **Services** — table of name, address, aliases, health, and source, plus the
   add/edit form.
3. **Records** — manual A, AAAA, CNAME, and PTR entries.
4. **Discovered** — live lease list with Promote buttons; shadowed entries
   marked.
5. **Settings** — tokens, import/export, cache flush, read-only config view.

Built on the existing design tokens in `css/styles.css` (`--bg #0d0f14`,
`--panel #161a22`, `--accent #4deeea`, Space Grotesk and IBM Plex Mono). That
stylesheet is a marketing theme with no app components, so table, form, badge,
and nav components go in a second stylesheet, leaving the marketing theme
untouched.

**Bug to fix:** all four `@font-face` rules in `css/styles.css` point at
`../assets/fonts/…`, but the fonts live in `fonts/`.

No JavaScript framework. About 30 lines of `fetch` on a timer refresh the health
and lease tables.

### Failure behavior

- **Snapshot rebuild is all-or-nothing.** Build fully, validate, then swap. A
  failed build logs and keeps serving the previous snapshot, so a bad edit can
  never take DNS dark.
- Config errors fail fast at startup. The process never runs half-configured.
- A failed store write returns 5xx and never touches the snapshot.
- An unreadable lease file logs, keeps the last known leases, and keeps serving.
  This satisfies the `DESGINE.md` goal of failing safely when a discovery source
  is unavailable.
- With every upstream down, forwarded queries get `SERVFAIL`; authoritative
  answers are unaffected.

### Testing

| Target | Approach |
|---|---|
| `registry` | Table-driven validation tests — the bulk of the value |
| `zone` | Precedence, PTR derivation, CNAME chains, collisions |
| `dnsserver` | Real handler on `127.0.0.1:0`, queried with a `miekg/dns` client; a second in-process server acts as the fake upstream |
| `cache` | TTL decrement, negative caching, eviction, and single-flight (concurrent misses produce exactly one upstream query) |
| `store` | Migrations against a temp-file database |
| `adminapi` | `httptest` against the real handler and a real temp store: auth required, validation errors, and an explicit test that export contains no hashes or credentials |
| `discovery/dhcp` | Parser tables using real dnsmasq lease fixtures, including junk hostnames |
| Integration | Boot the daemon on ephemeral ports, add a service over the API, resolve it over DNS |

SQLite is not mocked; temp files are fast enough.

## Dependencies

| Module | Why |
|---|---|
| `github.com/miekg/dns` | DNS wire protocol; writing it by hand is not viable |
| `modernc.org/sqlite` | Pure-Go SQLite, so builds stay cgo-free |
| `golang.org/x/crypto` | argon2id |
| `golang.org/x/sync` | `singleflight` for cache-miss collapsing |
| `gopkg.in/yaml.v3` | YAML export and import |

Everything else — HTTP, templates, embedding, logging via `log/slog` — is
standard library.

## Open items for the replication spec

- Change-log schema and the hook point in `store`.
- Node identity, peer enrollment, and mutual authentication.
- Whether health status replicates as operational metadata.

## Related documents

- `README.md` — product scope
- `DESGINE.md` — architecture
- `LOGGING.md` — logging and privacy requirements
- `SECURITY.md` — trust boundaries
- `CONTRIBUTING.md` — verification workflow
