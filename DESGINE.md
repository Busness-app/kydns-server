# KyDNS Design

## Purpose

KyDNS is a self-hosted DNS server and private service directory for homes,
homelabs, and small teams. It provides stable names for local services without
requiring clients to maintain hosts files.

The first release prioritizes reliable local naming, a small administrative web
UI, and linked servers that keep their configuration synchronized.

## Design goals

- Keep DNS data on the operator's network.
- Make service and record changes available from every linked server.
- Keep the runtime small and easy to back up.
- Separate administrative data from query history.
- Fail safely when a peer or discovery source is unavailable.

## System shape

Each KyDNS installation contains four logical parts:

1. **DNS server** — answers A, AAAA, CNAME, reverse, and service-name queries.
2. **Service registry** — stores services, aliases, addresses, checks, and
   metadata.
3. **Administration API/UI** — authenticates operators and applies changes.
4. **Replication agent** — exchanges authenticated configuration changes with
   linked KyDNS peers.

The DNS server reads from the local registry. DNS queries do not need to reach a
peer, so a temporary network partition does not stop local name resolution.

## Local data

The local store is the source of truth for the server's current view and must
contain:

- private-domain and DNS-view configuration;
- services and aliases;
- forward and reverse records;
- replication cursor and change metadata.

Discovery results and health-check status are runtime state, not stored data.
They are held in memory, re-derived from the lease source and health probes
after a restart, and kept out of backups. A discovered lease is persisted only
when an operator promotes it to a service.

Exports use YAML or JSON. Exports must omit upstream credentials, private keys,
and other secrets.

## Linked-server replication

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

1. An authenticated operator or discovery adapter submits a change.
2. The API validates the domain, record type, address, and permissions.
3. The local store commits the change before acknowledging success.
4. The replication agent sends the change to configured peers.
5. Peers apply it, acknowledge it, and expose the updated local DNS view.

Health-check status may be replicated as operational metadata, but query logs
remain local and configurable.

## Security and privacy

- Administrative endpoints require authentication and authorization.
- Peer enrollment requires an explicit operator action.
- Peer traffic is encrypted and mutually authenticated.
- Administrative and replication changes are logged locally.
- Query history is minimized by default and is not sent to KySecurity services.
- Public DNS names and private service names use separate configuration paths.

## Availability and recovery

Each server answers from its last successfully committed local state. When a
server restarts, it loads that state, resumes replication from its cursor, and
reconciles missed changes with peers.

Backups consist of the local registry plus replication metadata. Restoring a
server requires assigning or confirming its node identity before it rejoins a
replication group.

## Initial implementation boundary

The first implementation should include:

- one local DNS process;
- one service/record registry;
- authenticated administration;
- a simple web UI;
- explicit peer configuration and reliable change replication;
- structured privacy-safe logs.

The approved v1 design narrows this boundary: replication is deferred to its own
spec so the first release stays single-node. The store keeps a single write
chokepoint so the change log can be added without restructuring. See
`docs/superpowers/specs/2026-08-11-kydns-v1-design.md`.

Ad blocking, parental controls, device posture, traffic inspection, and
automatic peer discovery are outside the initial boundary.
