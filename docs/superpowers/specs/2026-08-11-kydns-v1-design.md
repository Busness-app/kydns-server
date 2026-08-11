# KyDNS v1 Design

Date: 2026-08-11
Status: Approved, ready for implementation planning

## Scope

KyDNS v1 is a single-node, self-hosted local DNS server and private service
directory. It answers authoritative queries for a private domain, forwards
everything else, discovers DHCP leases, checks service health, serves
split-horizon answers per client subnet, and exposes an authenticated admin API,
web UI, and CLI.

**Replication is out of scope for v1** and gets its own spec. `DESGINE.md`
lists it in the initial implementation boundary; that boundary is deliberately
narrowed here because replication roughly doubles the v1 surface area and is the
part least needed to make KyDNS useful. The design keeps a single write
chokepoint so the change log can be added later without restructuring.

Views (the `README.md` "separate views for home, VPN, guest, and lab networks")
**are in v1**, scoped to authoritative answers only. Views that select different
upstreams per client are deferred, because that variant would put the view into
the forwarder cache key. See [Part 4](#part-4--views).

Also out of scope, consistent with `DESGINE.md`: ad blocking, parental controls,
device posture, traffic inspection, automatic peer discovery. Additionally
deferred from the `README.md` capability list: Docker Compose discovery,
optional local TLS certificate issuance, and Pi-hole/AdGuard filter-list
integration.

### Decisions

| Decision | Choice |
|---|---|
| v1 scope | Single node; replication deferred |
| DNS engine | Go with `github.com/miekg/dns`, own server |
| Storage | SQLite via `modernc.org/sqlite` (pure Go, no cgo) |
| Admin UI | Server-rendered Go templates, `go:embed` |
| Auth | Single admin account plus API tokens |
| Extra v1 features | Health checks with status in the UI; DHCP lease discovery; per-subnet views |
| DHCP source | dnsmasq lease file as the reference adapter |
| Views | Match on client source IP; authoritative answers only |

## Part 1 — Shape and data

### Process and CLI

One binary, one process. `kydns` with subcommands:

- `serve` — the daemon
- `service`, `record`, `view`, `token`, `export`, `import` — admin operations

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
| `config` | Process config, a YAML file: bind addresses, private domain, reverse zones, ACL, upstreams, data dir, lease file, TTLs, intervals. Loaded before anything else. The DNS listener defaults to `:53` on UDP and TCP. Views are *not* here — they are registry data, see [Part 4](#part-4--views). |
| `store` | SQLite access and migrations. Every write goes through here — the one chokepoint where the replication change log later hooks in. |
| `registry` | Domain model, validation, and the application service both transports call. Services, aliases, records, views, precedence. Knows nothing about DNS wire format or HTTP. |
| `zone` | Builds an immutable snapshot from the registry: one forward and reverse index per view, plus the source-IP view matcher. |
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

The snapshot contains one index per view plus the view matcher, so a rebuild
costs the view count times the single-index build. With the handful of views a
homelab has, that stays in the microseconds.

### Persistence

Persisted in SQLite: services, aliases, records, views, the admin account
(argon2id hash), and API tokens (SHA-256 hashes). Service addresses and records
each carry a nullable view tag.

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

Precedence resolves independently within each view, against that view's
effective set (see [Part 4](#part-4--views)).

### Validation

Applied in `registry` before anything reaches the store:

- RFC 1035 label rules and length limits.
- Authoritative names must fall inside the configured private domain.
- A CNAME may not coexist with A/AAAA at the same name.
- An alias may not collide with an existing name.
- No wildcards in v1.
- A view tag must name a configured view.

The CNAME and alias-collision checks run per view against that view's effective
set, so an untagged CNAME conflicting with a view-tagged A record at the same
name is caught.

### Export and import

`kydns export` emits YAML or JSON containing views, services, aliases, and
records, with each address and record carrying its view tag when it has one.
It never emits the password hash, token hashes, or upstream credentials.
`kydns import` takes `--merge` or `--replace`, and treats a file with no views
block as fully untagged. This is the Git-based configuration workflow from
`README.md`.

## Part 2 — Query path, discovery, and health

### Pipeline

1. Parse the query. Non-`QUERY` opcodes get `NOTIMP`; non-`IN` classes get
   `REFUSED`.
2. Check the query ACL.
3. Resolve the client's view from its source IP.
4. Look for an authoritative match in that view's index.
5. Otherwise forward.

DNS clients are untrusted input (`SECURITY.md`). Nothing on this path can reach
the store.

### Access control

`allow_query` is a CIDR list defaulting to loopback plus RFC1918 and ULA ranges.
Everything else gets `REFUSED`. Default-closed, so a KyDNS accidentally exposed
on a WAN interface is not an open resolver.

`allow_tailscale` is a separate boolean, **default true**, that adds
`100.64.0.0/10` to the permitted set. Tailscale addresses live in CGNAT space
rather than RFC1918, so without it every tailnet client is refused — a
confusing failure to diagnose. It is a dedicated flag rather than a default list
entry so that closing the range is a one-line change: overriding `allow_query`
itself would otherwise force the operator to restate every other default.

Some ISPs also assign CGNAT addresses, so on a WAN-facing interface this range
is a small exposure. Operators who do not use Tailscale should set
`allow_tailscale: false`. The permitted ranges are logged at startup so the
effective policy is visible.

If `allow_tailscale` is false while a view holds CIDRs inside `100.64.0.0/10`,
that view can never match, because the ACL rejects those clients before view
resolution. This logs a warning rather than failing, since a subnet-router
deployment may legitimately use other addressing. Because views are registry
data rather than config, the check runs both at startup and whenever a rebuild
changes them.

### Authoritative answers

The server is authoritative for the configured private domain and for the
reverse zones named in config (for example `192.168.1.0/24`). Lookups run
against the index for the client's resolved view; "the zone" below means that
view's effective set. Within them:

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

Derivation happens inside each view's index from that view's effective
addresses. Adding `100.64.0.0/10` to the reverse zones therefore gives tailnet
clients working reverse lookups for tailnet addresses; a LAN client asking for
the same PTR gets `NXDOMAIN`, because that address is absent from its view.

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
source (authoritative, cache, or upstream), matched view, and duration. Logging
the client IP requires a second, separate flag. The view name is what makes
split-horizon behavior debuggable, and it is not additional client-identifying
data beyond the separately gated IP.

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

Health checks are view-agnostic. The check target is an explicit URL rather than
something derived from the service address, so there is nothing to disambiguate;
when KyDNS resolves that URL itself it uses the default view. A service
therefore has one health status, not one per view.

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
- `GET`/`POST` `/views`; `GET`/`PATCH`/`DELETE` `/views/{name}`
- `GET` `/leases`; `POST` `/leases/{ip}/promote`
- `GET` `/health` — per-service status
- `GET` `/stats` — cache and upstream counters
- `GET` `/export?format=yaml|json`; `POST` `/import?mode=merge|replace`
- `GET`/`POST`/`DELETE` `/tokens`
- `POST` `/cache/flush`
- `GET` `/healthz` — liveness, unauthenticated

A service's addresses are a list, each with an optional `view`. Records carry
the same optional field. Deleting a view is rejected with 409 while any address
or record still references it.

Errors return JSON with a machine-readable code, a message, and the offending
field name, so the CLI and the UI render the same validation failure. Status
codes: 400 validation, 401 unauthenticated, 403 unauthorized, 404 missing,
409 name collision or in-use view.

### Web UI

Five screens:

1. **Dashboard** — counts, upstream status, cache statistics, health summary.
2. **Services** — table of name, addresses, aliases, health, and source, plus
   the add/edit form. Addresses are a repeatable row of address plus view, so
   the Tailscale case is one extra row rather than a second service.
3. **Records** — manual A, AAAA, CNAME, and PTR entries, each with an optional
   view.
4. **Discovered** — live lease list with Promote buttons; shadowed entries
   marked.
5. **Settings** — views, tokens, import/export, cache flush, read-only config
   view. The views editor takes a name and a CIDR list, and shows which
   addresses and records reference each view.

Untagged addresses are labelled "all views" in the UI rather than shown with an
empty view column, since blank would read as "broken" instead of "everywhere".

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
- A view whose CIDRs are unreachable under the current ACL is a warning, not
  fatal: it is logged at startup and on any rebuild that changes views.
- A failed store write returns 5xx and never touches the snapshot.
- An unreadable lease file logs, keeps the last known leases, and keeps serving.
  This satisfies the `DESGINE.md` goal of failing safely when a discovery source
  is unavailable.
- With every upstream down, forwarded queries get `SERVFAIL`; authoritative
  answers are unaffected.

### Testing

| Target | Approach |
|---|---|
| `registry` | Table-driven validation tests — the bulk of the value; includes per-view CNAME and collision checks |
| `zone` | Precedence, PTR derivation, CNAME chains, collisions, per-view indexes, and untagged fallback |
| View matcher | Longest-prefix selection, IPv4 and IPv6, no-match falling through to default, duplicate CIDR rejected at write time |
| `dnsserver` | Real handler on `127.0.0.1:0`, queried with a `miekg/dns` client; a second in-process server acts as the fake upstream. Includes the split-horizon case: the same name queried from two source addresses returns two different answers |
| ACL | Tailscale range refused with `allow_tailscale: false` and answered with it true |
| `cache` | TTL decrement, negative caching, eviction, and single-flight (concurrent misses produce exactly one upstream query) |
| `store` | Migrations against a temp-file database |
| `adminapi` | `httptest` against the real handler and a real temp store: auth required, validation errors, and an explicit test that export contains no hashes or credentials |
| `discovery/dhcp` | Parser tables using real dnsmasq lease fixtures, including junk hostnames |
| Integration | Boot the daemon on ephemeral ports, add a service over the API, resolve it over DNS |

SQLite is not mocked; temp files are fast enough. The split-horizon test binds
its client to distinct loopback source addresses (`127.0.0.2`, `127.0.0.3`) via
a dialer `LocalAddr`, with views configured to match those `/32`s.

## Part 4 — Views

### Motivating case

A service reachable at `192.168.1.20` on the LAN and `100.x.y.z` over Tailscale
should answer to one name, `kypost.home.arpa`, from both. A tailnet client
cannot reach the RFC1918 address without a subnet router, so a single answer is
wrong for one side or the other.

### Model

A view is a name plus a CIDR list. Views are match rules, not containers.
Addresses and records carry an *optional* view tag; a query whose source IP
matches no view resolves to the empty tag, the default.

**Views live in the registry, not the config file.** They are edited through the
API and UI alongside the services that reference them, and they travel in
export/import so a restore is complete. The config file holds only the process
concerns — listeners, upstreams, the ACL.

**Untagged means everywhere.** A client in view `tailnet` gets the
`tailnet`-tagged addresses for a name if any exist, and otherwise the untagged
ones. Existing single-address services therefore keep working from every view
unchanged, and a tag is added only where the answer genuinely differs.

Falling back beats returning `NODATA`: the failure mode of a forgotten tag is
"resolves by the LAN path" rather than "name does not resolve at all".

As it appears in an export file:

```yaml
views:
  - name: tailnet
    subnets: ["100.64.0.0/10"]

services:
  - name: kypost
    addresses:
      - address: 192.168.1.20      # untagged: every view
      - address: 100.101.102.103
        view: tailnet
```

A LAN client matches no view and gets `192.168.1.20`. A tailnet client matches
`tailnet` and gets `100.101.102.103` only — not both, since a view-tagged
address for the name exists.

### Matching

Longest prefix wins, so a `/32` inside a view's `/24` resolves to the more
specific view. Because equal prefix lengths that overlap are by definition the
same network, the only ambiguous case is the same CIDR claimed by two views;
that is rejected at write time with 409, not discovered at query time.

Matching uses the source IP from `dns.ResponseWriter.RemoteAddr()`, which needs
no protocol extension and no client cooperation.

### What views do not touch

Views affect authoritative answers only. The forwarder cache is keyed on qname
and qtype with no view component, and stays exactly as specified in Part 2.
Per-view upstream selection — a guest view pointing at a filtered resolver — is
deliberately deferred, because it is what would force the view into the cache
key.

### Known limitation

Split-horizon keys on source IP, so it works only when clients query KyDNS
directly. A client pointed at an intermediate caching forwarder presents that
forwarder's address, and everyone behind it collapses into one view. Tailscale's
split-DNS setting queries the configured nameserver directly, so the motivating
case is unaffected.

The 60-second default TTL already limits staleness for a client roaming between
LAN and tailnet.

### Natural follow-on

A `discovery/tailscale` adapter reading the local `tailscaled` API could
auto-populate peer addresses, slotting in beside `discovery/dhcp` behind the
same interface shape. Not required for views and not in v1.

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
