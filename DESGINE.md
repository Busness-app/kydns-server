# KyDNS Design

## Purpose

KyDNS is a self-hosted DNS server and private service directory for homes,
homelabs, and small teams. It provides stable names for local services without
requiring clients to maintain hosts files.

The first release prioritizes reliable local naming, private upstream
forwarding, and a small administrative web UI. A single node is still the
normal deployment; linked-server replication is built on top of it, and a
second node is something an operator adds deliberately.

## Design goals

- Keep DNS data on the operator's network.
- Keep the path to an upstream resolver private, or fail loudly instead of
  quietly downgrading.
- Keep the runtime small and easy to back up.
- Separate administrative data from query history.
- Fail safely when a discovery source, health target, or upstream is
  unavailable.

## System shape

Each KyDNS installation contains eight logical parts, one Go package each:

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
6. **Settings** (`internal/settings`) — the process configuration that lives in
   the database, and the single path by which it changes.
7. **Replication agent** (`internal/replica`) — the node identity, the pairing
   exchange, the pinned TLS transport, and the loop that pulls configuration
   snapshots from a linked primary.
8. **DHCP server** (`internal/dhcpd`) — an optional DHCPv4 server on one
   interface. It implements the same lease-source interface as lease-file
   discovery, so the addresses it hands out reach DNS by the path that
   already existed. Node-local, and never on a replica: a primary or a
   standalone node may serve it, a replica never does.

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
  snapshot of each list's entries;
- the leases the built-in DHCP server has handed out.

Reverse records are derived from service addresses and the configured reverse
zones rather than stored.

The store also holds the server's own settings — the private domain, reverse
zones, upstreams, the query ACL, TTL and cache bounds, the logging opt-ins, the
built-in DHCP server's configuration, and the discovery and health intervals.
The config file owns exactly three keys
(`data_dir`, `dns.listen`, `admin.listen`), because the process needs them
before it has a database or a listening UI. Every other key the file carries
seeds the database on the first run and is ignored from then on: the database
wins, and an edit to the file after that start changes nothing.

List contents are data, not executable configuration: a downloaded list can
only add or remove blocked names, never run code or change how the server
behaves.

Discovery results and health-check status are runtime state, not stored data.
They are held in memory, re-derived from the lease source and health probes
after a restart, and kept out of exports. A discovered lease is persisted only
when an operator promotes it to a service.

The built-in server's own leases are the one exception, and for a reason that
does not generalize: this node issued them, so nothing else can re-derive them,
and handing an address out twice after a restart is the failure that matters.
They are written as they are granted, reloaded on boot with the expired rows
pruned in the same step, and never replicated or exported.

Exports use YAML or JSON and carry the settings block alongside the registry,
so a restored backup brings back the server's configuration too. Exports must
omit upstream credentials, private keys, and other secrets. A blacklist list URL may never embed credentials, so a
blacklist export, which carries list definitions and rules verbatim but never
the downloaded list bodies, cannot leak any either.

## Linked-server replication

Servers form an explicitly configured replication group with exactly one
primary. The primary accepts administrative writes; every other node is a
read-only replica that serves DNS from the configuration it last pulled. A
node is a primary, a replica, or standalone, decided by the `replication` keys
in its config file and by a promotion it has recorded, never inferred from the
network. It never changes role on its own.

A peer is identified by an Ed25519 key generated on first start; its node ID
is that key's fingerprint. The replication transport is a dedicated TLS
listener authenticated on pinned fingerprints alone. A mismatch is refused
outright — no prompt, no trust-on-next-use.

Peers are enrolled by a single-use, short-lived pairing code over that
transport, on the SSH model rather than as a PAKE: the joining node dials the
primary and reports the key it was presented, the operator compares it with
the one the primary printed, and only then is the code sent. The code
authorizes an enrollment; it never authenticates one. Confirmation and
transmission are two separate calls for that reason, so a peer the operator
declines receives nothing. Each side pins the other's fingerprint permanently
once the code is redeemed.

The primary keeps a `config_version` that is incremented in the same
transaction as any write to replicated state. A replica polls that version
and, when it differs, pulls the whole configuration as one document and
applies it in a single transaction. The configuration is kilobytes, so
shipping all of it is cheaper than the machinery needed to ship part of it,
and a replica that has been offline or has drifted converges on its next poll
with no catch-up path to get wrong.

Replicated: views, services, aliases, addresses, manual records, blacklist
list definitions and rules, and shared settings. Applying a snapshot rebuilds
the zone, settings, and policy snapshots in the same step: rows nothing has
read are not replication, and a replica that stored them without rebuilding
would keep answering with the configuration it had before the pull.

Not replicated: API tokens
and the admin account, which stay node-local so a compromised replica does
not surrender the group's credentials; blacklist list bodies, which each node
downloads itself; per-node settings such as the DHCP lease file, the built-in
DHCP server's own configuration, and query logging; the leases that server has
handed out; and DNS query history, ever.

Health status replicates as operational metadata, outside the configuration
version, and is what a replica renders for its own services: a replica sits on
the far side of the network from the services, so its own probes would answer
for a path no client takes. While its primary is unreachable — or before it has
been paired with one at all — it reports every service as unknown, never the
last value it saw. Stale-good health would show
a dead service as alive during exactly the outage an operator is reading it in.

An invalid or truncated snapshot leaves a replica's previous configuration
intact, so a bad pull degrades a replica to stale and never to broken.

### Roles and failover

A replica whose primary is unreachable keeps serving its last configuration
indefinitely and says so in the UI. It never promotes itself: clients already
list both servers, so an unreachable primary costs administration, not
resolution.

Promotion is a deliberate operator action — `kydns replica promote`, or the
button on the replication screen behind a confirmation — and the old primary
must be demoted or rebuilt before it returns. Two primaries serving the same
replicas is the one state this design cannot detect or reconcile, which is why
nothing here creates one automatically. Demotion re-pairs a former primary as a
replica and replaces its local configuration wholesale.

A promotion is recorded in the database rather than by editing the operator's
config file, and outranks a `replication.primary` still sitting in that file at
every later start: a node that has already accepted writes as a primary must
never come back following the key it was promoted away from. It opens no
listener either, so a promoted node serves no replicas until the operator sets
`replication.listen` and restarts. Both the CLI and the UI say so at the moment
of promotion.

The pull loop is built at startup from the pinned primary, so a node that has
just joined does not follow anything until it restarts with
`replication.primary` set. Pairing writes the pin; the config key and the
restart start the loop.

Because there is a single writer, there are no concurrent writes and so no
conflicts to resolve. An administrative audit log remains worth building, but
as its own feature rather than as a side effect of the replication transport.

Replication failures are visible in the administration UI and structured logs,
but do not make the local DNS server unavailable.

## Configuration flow

1. An authenticated operator, or an operator promoting a discovered lease,
   submits a change through the web UI or the JSON API.
2. The API validates the domain, record type, address, and permissions.
3. The local store commits the change before acknowledging success.
4. The DNS server picks up a fresh zone snapshot, so the next query sees it.

Three holders publish that state to the query path: the zone holder
(`internal/zone`), the policy holder (`internal/policy`), and the settings
holder (`internal/settings`). Each owns one immutable snapshot behind an atomic
pointer. A reader on the DNS hot path loads the pointer and never blocks; a
writer builds a complete new snapshot, and only swaps it in once the whole
snapshot exists. A change that fails to parse or validate therefore fails
before anything is published, and a query is answered from either the old
snapshot or the new one, never a half-applied mixture.

A settings change is validated, persisted, and applied in that order, all or
nothing, from whichever surface asked for it. Every setting the database owns
takes effect without a restart, including the DHCP lease file — the discovery
poller's source is swappable, so it is repointed in place — and the built-in
DHCP server's own keys, which reconcile its listener. The restart banner is
therefore comparing an empty set: it is the boot values against the stored
ones, so it cannot drift, and it is kept for the first key that needs it
again.

The private domain is applied live. The zone is an atomic on both the
authoritative answerer and the registry that validates new names, and each
answer reads it once so no reply straddles a change. Because manual records are
stored as full names, renaming the zone moves them in the same transaction as
the settings row: a half-applied rename would leave records outside the zone
the server now serves, answering nothing, with no way back but re-authoring
them. The administrative UI lists what will move and requires a second,
explicit save before any of it is written.

Query logs remain local and configurable.

## Security and privacy

- Administrative endpoints require authentication and authorization.
- Administrative changes are logged locally.
- Query history is minimized by default and is not sent to KySecurity services.
- Public DNS names and private service names use separate configuration paths.

## Availability and recovery

The server answers from its last committed local state. On restart it loads
that state, re-reads the lease source, and re-probes health targets. Leases the
built-in DHCP server issued are persisted and reloaded, with expired ones
pruned, so a restart cannot re-issue an address that is still in use.

A backup is the `data_dir` directory plus the config file. `kydns export`
writes the registry as YAML or JSON for the same purpose, which is what makes
Git-based configuration possible.

## Implementation boundary

Shipped in v1:

- one local DNS process with an ACL, cache, and encrypted forwarder;
- one service/record registry with per-subnet views;
- blacklist filtering;
- a built-in DHCP server, and DHCP lease discovery from one you already run;
- health checks;
- authenticated administration over a web UI, a JSON API, and a CLI;
- structured privacy-safe logs.

Linked-server replication has its own spec,
[`docs/superpowers/specs/2026-08-13-kydns-linked-server-replication-design.md`](docs/superpowers/specs/2026-08-13-kydns-linked-server-replication-design.md):
pairing, the pinned transport, the pull loop, the read-only replica, and
operator-driven promotion. Automatic failover, leader election, and more than
one primary are outside it.

Parental controls, device posture, traffic inspection, local DNSSEC validation,
local certificate issuance, and automatic peer discovery are outside the
boundary. Blacklist filtering is specified in
[`docs/superpowers/specs/2026-08-12-kydns-blacklists.md`](docs/superpowers/specs/2026-08-12-kydns-blacklists.md).
