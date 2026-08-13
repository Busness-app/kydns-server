# Linked-server replication

Status: approved
Date: 2026-08-13

## Why

KyDNS is single-node. When the box running it goes down, every name on the
network goes with it — which is the one failure a homelab notices within
seconds, because nothing resolves.

Clients already accept more than one DNS server. This adds a second KyDNS
that carries the same configuration, so a client's second entry answers the
same names as its first. The goal is availability, not scale.

`DESGINE.md` reserved this from the start: `internal/store` is the single
write chokepoint precisely so replication could be added without
restructuring. This spec fills that reservation, and revises the deferred
sketch — see [Departures from the deferred sketch](#departures-from-the-deferred-sketch).

## Decisions

| Question | Decision |
|---|---|
| Who writes | One primary. Replicas are read-only. |
| How data moves | Versioned snapshot pull, not a change log. |
| Transport | Dedicated TLS listener, peers pinned by key fingerprint. |
| Enrollment | Operator confirms the primary's fingerprint, then a short-lived single-use code authorizes the replica. |
| What replicates | Views, services, records, aliases, blacklist definitions and rules, shared settings, health status. |
| What does not | Tokens, the admin account, blacklist list bodies, node-local settings, query history. |
| Primary down | Replica keeps serving. Never self-promotes. |
| Promotion | Explicit operator action. |

## Scope

### Replicates

- Views and their subnets
- Services, their addresses and aliases, check and proxy configuration
- Manual records
- Blacklist list *definitions* and allow/deny rules, and the filtering toggle
- Shared settings (below)
- Health status, as operational metadata outside the config version

### Does not replicate

| Excluded | Why |
|---|---|
| API tokens, admin account | Node-local credentials. Replicating them means compromising the weakest-secured replica hands over every credential in the group. |
| Blacklist list bodies | Each node downloads its own on its own schedule, so filtering survives a primary outage. Keeps the snapshot in kilobytes. |
| `dhcp_lease_file`, `discovery.interval` | Point at a file on one host. |
| `log_queries`, `log_client_ip` | A per-node privacy choice. |
| `data_dir`, `dns.listen`, `admin.listen`, `replication.*` | File-owned; per-node by definition. |
| DHCP lease discoveries | Each node reads its own lease file. A lease becomes replicated state only when an operator promotes it to a service, which is a write and therefore happens on the primary. |
| Query history | `DESGINE.md` already forbids it. Unchanged. |

### Settings split

`snapshotDoc()` currently emits every setting. The settings DTO splits into a
replicated set and a node-local set. A replica takes the replicated set from
the primary and keeps its own node-local keys; the merge never overwrites a
local key.

Replicated: `private_domain`, `reverse_zones`, `upstreams`, `allow_query`,
`allow_tailscale`, `ttl`, `cache_min_ttl`, `cache_max_ttl`,
`negative_max_ttl`, `cache_entries`, `health.interval`, `health.timeout`,
`health.workers`.

Node-local: `dhcp_lease_file`, `discovery.interval`, `log_queries`,
`log_client_ip`.

The same split applies to the export file, so a backup states which keys
travel and which do not.

## Node identity and roles

A new `internal/replica` package owns identity, pairing, the listener, and
the poll loop.

Two new file-owned configuration keys join `data_dir`, `dns.listen`, and
`admin.listen`, because they are needed before the database is usable:

```yaml
replication:
  # Primary only. The TLS replication listener. Empty means replication off.
  listen: ""
  # Replica only. The primary's replication address. Empty means not a replica.
  primary: ""
```

Setting both is a startup error naming both keys. A node is a primary, a
replica, or standalone — never ambiguous, and never inferred.

On first start with either key set, the node generates an Ed25519 keypair in
`data_dir` at mode `0600`. The node ID is the public key fingerprint, so
identity is the key rather than a name two operators could collide on.

## Pairing

Enrollment answers two separate questions, and the design keeps them
separate. *Is this really my primary?* is answered by the operator comparing
a fingerprint. *Is this replica allowed to enroll?* is answered by the
pairing code.

1. On the primary, *Add replica* in the UI or `kydns replica invite` mints a
   pairing code — human-typable, single-use, valid ten minutes — and displays
   the primary's own key fingerprint beside it.
2. On the replica, the operator supplies the primary's address and the code.
3. The replica dials, reads the certificate the primary presents, and shows
   the operator the fingerprint it computed: *the primary presented `ab:cd:…`
   — does that match what the primary displays?*
4. The operator confirms. **Only then** does the replica pin that fingerprint
   and send the code.
5. The primary redeems the code and pins the replica's fingerprint, taken
   from the client certificate on the same connection. The code is spent.
6. Every later connection authenticates on pinned fingerprints alone.

**The order in step 4 is the security property, not a detail.** The code is
sent only after the operator has vouched for the far end, so it never crosses
an unauthenticated channel. An attacker in the path presents its own
certificate and therefore its own fingerprint, which does not match what the
primary displays, and the operator stops before anything is sent. The
attacker never learns the code and so can never enroll itself.

This is the SSH model, and it is here because no Go PAKE qualified. The full
evaluation is in
[the PAKE selection](2026-08-13-kydns-pake-selection.md): nothing in Go
currently offers a reviewed, maintained, specified balanced PAKE. A PAKE
would have removed the comparison step; without one, an operator comparing a
short string across two screens once per replica is the honest price of
closing the same hole. Should a reviewed implementation appear, it would
replace steps 3 and 4 and nothing else.

Sending the code as a bearer token *before* the confirmation, hashing it, or
running an HMAC challenge-response over the connection are all still
excluded, and for the original reason: until the operator has vouched for the
certificate, an attacker in the path completes the exchange with each side in
turn and ends up pinned by both.

For scripted installs, `kydns replica join` accepts the expected fingerprint
as an argument. Supplying it is the same assertion the operator makes by
eye, moved into the automation that already knows both hosts. Pairing never
proceeds without one or the other — there is no prompt-free default that
trusts whatever answered.

A fingerprint mismatch after pairing is a hard failure: refuse the
connection, log it at error with both fingerprints, and raise a UI banner.
There is no prompt to accept and no trust-on-next-use.

Removing a replica on the primary drops its fingerprint and takes effect on
that replica's next poll, which is refused. The replica then reports that it
has been unlinked and keeps serving its last configuration.

## Sync

### Primary

A `config_version` integer in the store is incremented in the same
transaction as any write touching replicated state. `internal/store` is
already the sole write chokepoint, so this is one place. Writes to
node-local state — a token, the admin password, a local settings key — do
not bump it.

Two read-only endpoints on the replication listener:

| Endpoint | Returns |
|---|---|
| `GET /replica/version` | `{node_id, config_version, schema_version}` |
| `GET /replica/snapshot` | The `snapshotDoc()` document plus the version it was taken at |

The version is read *before* the body. A write landing between the two ships a
body newer than the version stamped on it, and the replica pulls again on the
next tick; the other order would have it record a version for a configuration
it never received and stop asking. Newer-than-stamped is self-correcting;
older-than-stamped is silent divergence.

The replica reports the version it holds on `/replica/version`, and that is
what the primary records as the peer's version. The primary's own version says
nothing about how far behind a replica is.

`GET /replica/health-status` serves health separately, outside the config
version, because health changes constantly and must not invalidate
configuration. **Part 2, not yet implemented.**

### Replica

Poll `/replica/version` every five seconds. An unchanged version — the
overwhelmingly common case — costs a few hundred bytes and does nothing. A
changed version fetches the snapshot, applies it in one transaction, and
records the new version. The apply reuses the existing import-replace path,
which already leaves local credentials alone.

Health is fetched on the same tick. When the primary is unreachable, health
displays as **unknown**, never as the last known value: an unreachable
primary must not make a dead service look alive.

Blacklist bodies never cross the wire. The replica receives list definitions
in the snapshot and runs its own downloader, exactly as a standalone node
does, so filtering keeps working through a primary outage with no special
case.

Lists are matched by name on apply, so renaming one on the primary costs every
replica a re-download of that list. That is the price of not shipping bodies,
and renaming a list is rare.

### Failure handling

| Failure | Behavior |
|---|---|
| Snapshot invalid, truncated, or fails validation | Keep the previous configuration entirely. Surface the error. A bad snapshot degrades a replica to stale, never to broken. |
| `schema_version` mismatch | Refuse the snapshot, naming both versions, so upgrading the primary first cannot corrupt a lagging replica. |
| Primary unreachable | Keep serving. Back off polling to a 60-second ceiling. Show time since last sync, and a standing banner once it exceeds 60 seconds — twelve missed polls, long enough that a restart or a brief network blip does not raise one. |
| Fingerprint mismatch | Refuse, log at error, banner. No fallback. |

Replication failure is always visible and never makes local DNS
unavailable.

## Operator surface

### Read-only enforcement

A single middleware in `adminapi` rejects every mutating method on a replica
with `409 Conflict` and a body naming the primary's address. One rule at one
chokepoint, so an endpoint added later cannot silently accept writes.

Read paths stay fully open: a replica's dashboard, query statistics,
blacklist status, and logs are its own and live.

The web UI reads the role from the existing settings response and renders
edit controls **disabled** with "Managed by *primary*". Disabled explains
itself; hidden reads as a bug.

The CLI fails the same way, before touching the network, with the primary's
address in the message.

### CLI

| Command | Effect |
|---|---|
| `kydns replica invite` | Mint a pairing code. Primary. |
| `kydns replica join <address> <code>` | Pair with a primary. |
| `kydns replica list` | Peers, last sync, version lag, status. |
| `kydns replica remove <node-id>` | Unpair. Primary. |
| `kydns replica promote` | Promote this replica to primary. |

Each mirrors a UI control, as every other KyDNS surface does.

### Dashboard

A primary lists its replicas with each one's last successful sync. A replica
names the primary it follows and how long since its last sync, with a
standing banner once that exceeds 60 seconds.

### Promotion and demotion

`kydns replica promote`, or the UI button behind a confirmation, flips a
replica to primary: it begins accepting writes, keeps its current
configuration as the new truth, and clears `replication.primary`.

The confirmation states plainly that the old primary must be demoted or
rebuilt before it returns. Two primaries serving the same replicas is the one
genuinely bad state here, and no part of the protocol can detect it. There is
deliberately no automatic reconciliation: the honest resolution is that an
operator picks which node is correct and re-pairs the other, which reduces to
a fresh snapshot pull.

`kydns replica join` on a former primary demotes it, and its next poll
overwrites its local configuration wholesale. That is destructive, so the CLI
names what it will discard and requires confirmation.

## Testing

Every security property below is tested, not asserted. Each test must be
shown to fail against the unfixed code before it is trusted.

**Pairing**

- A wrong code is rejected.
- An expired code is rejected.
- A spent code is rejected.
- After pairing, a peer presenting a different fingerprint is refused, with
  no prompt and no fallback.
- The code is not sent before the operator confirms. A pairing attempt
  against a peer whose fingerprint the operator rejects transmits no code at
  all — asserted against the wire transcript, since this ordering is the
  whole reason the SSH model closes the same hole a PAKE would have.
- A machine-in-the-middle presenting its own certificate produces a
  fingerprint that does not match the primary's, so the confirmation fails
  and the attacker learns nothing.
- `join` with an explicitly supplied fingerprint that does not match what the
  peer presents fails without prompting and without sending the code.

**Version discipline**

- A service write bumps `config_version`; a token write does not.
- A snapshot's body is never *older* than the version stamped on it, under
  concurrent writes. A newer body is allowed and self-corrects on the next
  tick; an older one would strand the replica at a version it never received.
- The version a peer is recorded at is the one the replica reported, not the
  one the primary read out of its own store.

**Apply safety**

- Applying a snapshot leaves the replica's tokens and admin account
  untouched.
- It takes replicated settings and preserves node-local ones.
- A malformed or truncated snapshot leaves the previous configuration
  intact — asserted by resolving a name through the replica afterward, not
  by reading the database.
- A `schema_version` mismatch is refused, naming both versions.

**Write gating**

- A table over every mutating route in `adminapi`, so a route added later
  without thought fails the test rather than accepting writes on a replica.

**End to end**, two nodes in one process

- Pair them; add a service on the primary; the replica answers the new name.
- Kill the primary; the replica still answers, and its health display goes
  to unknown rather than staying green.
- Promote the replica; it accepts a write.
- Re-pair the old primary as a replica; its divergent local configuration is
  replaced.

## Departures from the deferred sketch

`DESGINE.md` sketched multi-writer replication: an immutable ordered change
log, changes exchanged by ID and acknowledged, and deterministic
last-write-wins conflict resolution.

This spec chooses a single writer, which removes the reason that machinery
existed. A change log merges concurrent writes from multiple authors; with
one author there are no concurrent writes to merge, and no conflicts to
resolve. What the log would still provide is an audit trail — real value,
but an administrative-audit feature that should stand on its own rather than
dictate the replication transport.

Snapshot pull is also self-healing in a way an incremental log is not. A
replica offline for a week, or drifted for any reason, converges on its next
poll. There is no catch-up path, no log retention window, and no compaction
for new joiners — because there is nothing to catch up on.

The cost is honest: every change ships the whole configuration, and a replica
learns that configuration changed but not what changed. At the scale KyDNS
targets, the whole configuration is kilobytes.

`DESGINE.md` is updated to describe this model.

## Out of scope

- Automatic peer discovery. Peers are explicitly paired.
- Automatic failover or leader election.
- Replicating query history, in any form.
- More than one primary.
- An administrative audit log. Worth building; not this.
