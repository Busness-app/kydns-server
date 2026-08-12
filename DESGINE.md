# KyDNS Design

## Purpose

KyDNS is a self-hosted DNS server and private service directory for homes,
homelabs, and small teams. It provides stable names for local services without
requiring clients to maintain hosts files.

The first release prioritizes reliable local naming, private upstream
forwarding, and a small administrative web UI. It is single-node; linked-server
replication is designed here but deferred to a later release.

## Design goals

- Keep DNS data on the operator's network.
- Keep the path to an upstream resolver private, or fail loudly instead of
  quietly downgrading.
- Keep the runtime small and easy to back up.
- Separate administrative data from query history.
- Fail safely when a discovery source, health target, or upstream is
  unavailable.

## System shape

Each KyDNS installation contains six logical parts, one Go package each:

1. **DNS server** (`internal/dnsserver`, `internal/upstream`) — the query ACL,
   the authoritative answer path, the cache, and the DoT/DoH forwarder.
2. **Zone/registry** (`internal/zone`, `internal/registry`, `internal/store`) —
   services, aliases, addresses, manual records, views, reverse zones, and the
   SQLite store behind them.
3. **Policy engine** (`internal/policy`) — blacklist list parsing, refresh, and
   the deny/allow/list decision.
4. **Administration API and UI** (`internal/adminapi`, `internal/web`,
   `internal/auth`) — authenticates operators and applies changes.
5. **Discovery and health** (`internal/discovery`, `internal/health`) — reads
   DHCP leases and probes service check URLs.
6. **Replication agent** — *deferred.* Would exchange authenticated
   configuration changes with linked KyDNS peers.

The DNS server reads from the local registry, so local name resolution does not
depend on any network beyond the host.

A query is resolved in a fixed order: the query ACL, then the authoritative
lookup against the local registry (services, aliases, records, and reverse
zones), then, only for names the authoritative lookup declines, the policy
engine. A blocked name gets a synthesized local NXDOMAIN; everything else
falls through to the cache and forwarder. A local service or record can
therefore never be blocked, because the policy engine never sees a name the
authoritative lookup already answered.

## Upstream forwarding

Names KyDNS is not authoritative for go to the configured upstreams in order,
over DNS-over-TLS or DNS-over-HTTPS, with certificate verification always on.
An upstream host must be an IP address, because a hostname would need DNS to
resolve it and KyDNS may be that DNS. Identical concurrent misses are collapsed
by single-flight, and answers are cached with the TTL clamped to the configured
bounds.

If every encrypted upstream fails, clients get `SERVFAIL`. Falling back to
plain DNS is exactly what an attacker who blocks port 853 wants, so it is not
automatic: an operator opts in per upstream with a `udp://` entry, and anything
that entry answers has its authenticated-data bit cleared.

KyDNS does not validate DNSSEC itself. It makes the path to a resolver that
does private and tamper-proof, and passes that resolver's verdict through.

## Local data

The local store is a single SQLite file under `data_dir`. It is the source of
truth for the server's current view and contains:

- views and their subnets;
- services, their addresses, and aliases;
- manual forward records;
- the admin password hash and API tokens;
- blacklist list definitions and refresh metadata (URL, format, interval, last
  status), one-off allow/deny rules, and the last known-good normalized
  snapshot of each list's entries.

Reverse records are derived from service addresses and the configured reverse
zones rather than stored. The private domain and reverse zones come from the
config file, which is read once at startup: changing it requires a restart.

List contents are data, not executable configuration: a downloaded list can
only add or remove blocked names, never run code or change how the server
behaves.

Discovery results and health-check status are runtime state, not stored data.
They are held in memory, re-derived from the lease source and health probes
after a restart, and kept out of backups. A discovered lease is persisted only
when an operator promotes it to a service.

Exports use YAML or JSON. Exports must omit upstream credentials, private keys,
and other secrets. A blacklist list URL may never embed credentials, so a
blacklist export, which carries list definitions and rules verbatim but never
the downloaded list bodies, cannot leak any either.

## Linked-server replication (deferred)

None of this section is implemented. It is recorded so the shipped design does
not foreclose it: the store keeps a single write chokepoint, so the change log
can be added without restructuring.

Servers form an explicitly configured replication group. A peer is identified
by its node ID and endpoint, and must be authenticated before it can exchange
data.

Every administrative or discovered configuration change is recorded as an
immutable change with:

- a globally unique change ID;
- the originating node ID;
- the affected resource and operation;
- the resulting resource value;
- an ordering value and schema version.

Peers exchange changes by ID, apply each change idempotently, and acknowledge
the highest contiguous set they have stored. Retried delivery is safe, and
offline peers catch up after reconnecting.

The replication transport must use encrypted, mutually authenticated links.
Replication must never include DNS query history by default.

### Conflicts

The initial design uses deterministic last-write-wins for the same resource:
the ordering value wins, with node ID as the tie-breaker. A losing update is
retained in the change log for audit and troubleshooting. Future versions may
add operator-selected authority for resources that should not be multi-writer.

Replication failures are visible in the administration UI and structured logs,
but do not make the local DNS server unavailable.

## Configuration flow

1. An authenticated operator, or an operator promoting a discovered lease,
   submits a change through the web UI or the JSON API.
2. The API validates the domain, record type, address, and permissions.
3. The local store commits the change before acknowledging success.
4. The DNS server picks up a fresh zone snapshot, so the next query sees it.

Query logs remain local and configurable.

## Security and privacy

- Administrative endpoints require authentication and authorization.
- Administrative changes are logged locally.
- Query history is minimized by default and is not sent to KySecurity services.
- Public DNS names and private service names use separate configuration paths.

## Availability and recovery

The server answers from its last committed local state. On restart it loads
that state, re-reads the lease source, and re-probes health targets.

A backup is the `data_dir` directory plus the config file. `kydns export`
writes the registry as YAML or JSON for the same purpose, which is what makes
Git-based configuration possible.

## Implementation boundary

Shipped in v1:

- one local DNS process with an ACL, cache, and encrypted forwarder;
- one service/record registry with per-subnet views;
- blacklist filtering;
- DHCP lease discovery and health checks;
- authenticated administration over a web UI, a JSON API, and a CLI;
- structured privacy-safe logs.

Replication is deferred to its own spec so the first release stays single-node.
See `docs/superpowers/specs/2026-08-11-kydns-v1-design.md`.

Parental controls, device posture, traffic inspection, local DNSSEC validation,
local certificate issuance, and automatic peer discovery are outside the
boundary. Blacklist filtering is specified in
[`docs/superpowers/specs/2026-08-12-kydns-blacklists.md`](docs/superpowers/specs/2026-08-12-kydns-blacklists.md).
