# Built-in DHCPv4 server

Status: approved
Date: 2026-08-19

## Why

The hardest step in deploying KyDNS is the one it cannot do anything about:
pointing clients at it. The README's answer is to change the DNS server the
router advertises, and a large share of consumer and ISP-supplied routers do
not allow that. For those operators there is no self-service path — the
product works perfectly and nobody's laptop uses it.

Owning DHCP is the only thing that solves this. Advertising ourselves in
option 6 is the whole point; every other feature here exists to make that
safe.

This is deliberately the Pi-hole-shaped feature, not the Technitium-shaped
one. One subnet, one interface, a range, and reservations. The moment it
grows scopes and relays it stops being the low-friction half of the product
it was added to serve.

## Decisions

| Decision | Rationale |
|---|---|
| One scope, one interface, IPv4 only | The friction problem is a single home or small-office LAN. Scopes and relays serve routed networks that already have a DHCP server someone chose. |
| Off by default, always opt-in | A second DHCP server on a segment breaks the whole network, not one name. |
| Refuses to enable when another server answers | The one failure that ruins an evening, detected before it can happen. |
| `internal/dhcpd` implements `discovery/dhcp.Source` | Leases reach DNS through the path that already exists. No new plumbing into the zone snapshot. |
| A reservation is an optional MAC on a `Service` | Naming a host and pinning its address become one action on one screen. |
| Settings are node-local; a replica never serves DHCP | Matches how `dhcp_lease_file` is already treated, and two DHCP servers on one segment is the thing we are protecting against. |
| Host networking or a native install only | DHCP needs L2 broadcast reach. Bridge-mode Docker cannot have it, and a half-working DHCP server is worse than an absent one. |

## Scope

### In

- A DHCPv4 server on one interface: DISCOVER/OFFER, REQUEST/ACK/NAK,
  DECLINE, RELEASE, INFORM.
- Persistent leases in the existing SQLite file.
- Reservations, as a MAC on a service.
- Conflict probing before an address is offered.
- Rogue-server detection on enable, at startup, and periodically.
- A setup wizard that pre-fills every field from the host's own interface.
- A DHCP tab: the toggle, the fields, and a live lease table.

### Out

Named here so they are refused rather than re-litigated:

- **DHCPv6 and router advertisements.** SLAAC means we would not own IPv6
  addressing anyway, and the surface is larger than the rest of this
  document combined. This has a consequence on dual-stack networks; see
  below.
- **Multiple scopes.**
- **Relay support (`giaddr`) and option 82.** Serving a subnet we are not
  attached to requires scope selection, which requires multiple scopes.
- **Vendor classes and per-host options.**
- **PXE (`next-server`, `filename`).** Two fields and a popular request, but
  it is the first step onto the path this feature exists to avoid.
- **Failover or HA between linked servers.** See "Replication" for what
  happens instead.
- **BOOTP.**

### Known limitation: dual-stack networks leak to the router's resolver

Leaving IPv6 out means DHCP does not fully deliver what it promises on a
dual-stack LAN, and that is expected behaviour rather than a bug.

In IPv4, disabling the router's DHCP server leaves clients nowhere else to
go, so they take our option 6. IPv6 configuration comes from the router's
Router Advertisements instead, and an RA carrying an RDNSS option (RFC 8106)
hands clients the router's resolver directly. A client on such a network ends
up holding both: KyDNS over IPv4 from us, and the router over IPv6 from the
RA. Stub resolvers commonly prefer the IPv6 server.

The symptoms are intermittent rather than total, which is what makes this
worth writing down. Filtering appears to work and then does not. A local
service name resolves and then does not. Nothing in KyDNS's own logs shows a
query, because the query never arrived.

This is not hypothetical for the networks we target: residential IPv6 is
widely deployed, including on Verizon's consumer service.

The operator-side workarounds, in order of preference:

1. Turn off the RDNSS/IPv6-DNS advertisement on the router, keeping IPv6
   addressing.
2. Failing that, turn off IPv6 on the router entirely — a real cost, and
   some consumer routers offer no finer control.
3. Accept the leak and treat filtering as best-effort.

The DHCP tab says this where an operator will see it, rather than leaving it
in a spec. When DHCP is enabled and the host has a global IPv6 address —
evidence the segment is dual-stack — the tab shows a short note naming the
leak and the first workaround. It is informational, never a blocker.

The fix, if it is ever wanted, is an RA sender advertising ourselves as an
RDNSS with Router Lifetime 0 (options without becoming a default router),
plus stateless DHCPv6 for clients that ignore RDNSS. That is IPv6 DNS
advertisement, and it is a much smaller feature than DHCPv6 addressing. It
is out of scope here and deliberately not scheduled.

## Deployment constraints

DHCP needs to hear broadcasts from clients, so it is available in exactly
two deployments:

- a native package install, and
- Docker with `network_mode: host`.

In bridge mode the DHCP tab renders the feature as unavailable with the
reason, and the settings validator refuses to enable it. An interface
qualifies when it exists, is up, is not loopback, has an IPv4 address with a
prefix, and `/sys/class/net/<iface>/uevent` does not report `DEVTYPE=veth`.
The veth check is what catches bridge mode, where everything else would pass
and the server would bind happily and serve nobody.

When no interface qualifies, the UI names the two supported deployments. It
does not offer a workaround, because there is not a good one.

`packaging/` adds `AmbientCapabilities=CAP_NET_BIND_SERVICE` to the systemd
unit so port 67 binds as the unprivileged `kydns` user without the operator
doing anything.

## Sockets

`github.com/insomniacslk/dhcp/dhcpv4`, with a UDP socket bound to
`0.0.0.0:67` and `SO_BINDTODEVICE` pinned to the configured interface.
Replies are broadcast.

Broadcasting every reply is the simplification that keeps this to one
capability and no raw sockets. It is correct for clients that set the
broadcast flag and works in practice for nearly all that do not, because
they are listening on `0.0.0.0:68` regardless. If a client turns up that
genuinely requires a unicast reply to an address it does not yet have, the
fallback is an `AF_PACKET` writer behind the same interface, needing
`CAP_NET_RAW`. That is a later change, not a v1 one, and this section exists
so the reason is on record when it happens.

## Settings

A new node-local block in the settings row. Nothing here is replicated and
nothing here lives in `kydns.yaml`.

| Key | Default | Notes |
|---|---|---|
| `dhcp.enabled` | `false` | Binds or closes the listener live. |
| `dhcp.interface` | none | Rebinds live. |
| `dhcp.range_start`, `dhcp.range_end` | none | Must be inside the interface's subnet. |
| `dhcp.gateway` | host default route | Option 3. |
| `dhcp.lease_seconds` | `86400` | Clamped to 300–604800. |
| `dhcp.secondary_dns` | empty | Optional second entry in option 6. |

The subnet mask is read from the interface, not typed. The search domain is
always `private_domain`; there is no setting. Option 6 always leads with
KyDNS's own address on that interface.

`secondary_dns` exists because the README tells operators to give clients two
resolvers for exactly the outage this feature would otherwise make worse.
Turning on DHCP must not silently undo that advice.

### Applying without a restart

`discovery.Poller` gains `SetSource`. Today the poller is constructed with
its source and wired into the snapshot builder at boot, which is the only
reason `dhcp_lease_file` requires a restart. With a swappable source, both
that key and `dhcp.enabled` apply live.

That is a change to existing behaviour: `dhcp_lease_file` moves from the
restart-required list to the applied-live list in `README.md` and in
`2026-08-13-kydns-settings-in-the-ui-design.md`. `private_domain` stays
where it is.

The built-in server and the lease-file poller are mutually exclusive. The
settings validator rejects `dhcp.enabled` with a non-empty
`dhcp_lease_file`, naming the other key.

## Lease allocation

### Store

A new table in the existing database:

```
dhcp_leases(
  mac        TEXT PRIMARY KEY,
  ip         TEXT NOT NULL UNIQUE,
  hostname   TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  last_seen  INTEGER NOT NULL
)
```

Leases are reloaded on boot and unexpired ones are honoured, so a restart
cannot re-issue an address that is in use. Expired rows are pruned lazily on
allocation, not by a timer.

### Order

1. The MAC has a reservation → that address, always, even if it is inside
   the dynamic range.
2. The MAC has an unexpired lease whose address is still in range and not
   reserved to another MAC → renew it.
3. The client requested an address (option 50) that is free → grant it.
4. Otherwise the lowest free address in the range.

Reserved addresses are excluded from dynamic allocation whether or not they
fall inside the range.

### Conflict probing

Before offering an address that is new to us — not a renewal, not a
reservation — an ARP lookup on a 100 ms budget. A reply quarantines that
address for 10 minutes and allocation moves on.

*Amended in implementation.* The ICMP echo this originally paired with the ARP
lookup is not built: it would need `CAP_NET_RAW`, which this service does not
have and will not be granted, so there is one socket mechanism here and not
two (`internal/dhcpd/probe.go`).

A DHCPDECLINE quarantines an address the same way, but only from the client
that actually holds it, and only for an address inside the dynamic range: a
decline is an unauthenticated broadcast, so honouring one from anybody would
let a forged packet delete any lease on the segment and fill the quarantine
map. That excludes a **promised** reserved address. When the client already
holds a different lease, an OFFER promises the reservation without committing
a lease for it, so `Allocator.Decline` refuses the decline and nothing is
quarantined — which changes nothing anyway, because rule 1 hands out a
reservation without consulting the quarantine list. The server logs that the
reserved address is already in use instead, which is the part the operator has
to act on. That branch is the only one that promises: an OFFER to a client
holding no other lease commits, so a decline from that client is honoured —
the lease is dropped, and the address is quarantined as well when it falls
inside the dynamic range.

The quarantine list is in memory. Losing it on restart is fine: the probe
runs again.

### Range exhaustion

No free address means no OFFER, a warning log, and a banner in the UI naming
the range and its size. We do not steal the oldest lease.

## Names

Leases publish through `discovery/dhcp.Lease` and reach DNS through the
existing snapshot path, so all of today's rules hold unchanged: a service
shadows a lease of the same name (`TestServiceBeatsLease`), a service PTR
beats a lease PTR, and the hostname is validated and lowercased before it is
published.

Option 12 is attacker-controlled — it is a string chosen by any device on
the LAN. Two rules follow:

- A lease can never shadow a service, an alias, or a manual record. This
  already holds and is the reason a device cannot claim `router.home.arpa`
  out from under a real one.
- Between two leases, first claim wins for the life of that lease. A second
  client asking for a name already held by a different MAC still gets an
  address; it just gets no DNS name, and the collision is logged once.

A device that sends no hostname gets an address and no name. We do not
synthesize one from the MAC.

## Rogue-server detection

A probe: a DISCOVER from a random locally-administered MAC on the configured
interface, with a 2 s wait for OFFERs whose server identifier is not us.

- **On enable and at startup**, a positive result refuses to start the
  listener and reports the other server's IP and the address it offered.
- **An override** exists for operators who genuinely run two servers. It is
  off by default and the UI shows what was detected next to it.
- **Every 15 minutes while running**, the same probe raises a UI banner and
  a warning log if another server appears.

The periodic probe never disables the listener. Pulling DHCP out from under
a working network because of one transient answer is worse than the conflict
it would be reacting to.

## Reservations

`Service` gains an optional `MAC`.

The reserved address is **the unique service address that falls inside the
DHCP subnet**. Zero such addresses, or more than one, and the reservation is
inactive and flagged on the service in the UI. This rule is what lets
per-view addresses exist without a second concept: a service answering
differently on the LAN and over a VPN has exactly one LAN address, which is
the one DHCP can reserve.

MACs are normalized on write to lowercase colon-separated form and are unique
across services. A lease's MAC is normalized the same way, so the two always
compare directly.

The lease table's `Reserve` button promotes a lease to a service with its MAC
and address filled in, reusing the existing promote-to-service flow.

## Replication

- `dhcp.*` is node-local, exactly as `dhcp_lease_file` already is.
- Reservations are service configuration and replicate with everything else.
- **A replica never starts the listener**, whatever its local `dhcp.enabled`
  says. Promotion starts it.
- Dynamic leases never replicate.

The consequence, stated plainly: a promoted replica has every reservation but
an empty lease table, and will re-allocate dynamic addresses from scratch.
Conflict probing is what keeps that from handing out an address in use, and
clients whose leases it does not know will be NAKed and re-DISCOVER. This is
a known limitation of choosing not to build failover, not an oversight.

## Setup wizard

Enabling reads the chosen interface and pre-fills everything:

- **Range** — the upper half of the subnet, excluding the host's own address
  and the gateway. For a `/24` on `192.168.1.0`, `.128`–`.254`.
- **Gateway** — the host's default route.
- **DNS** — this server.
- **Lease** — 24 hours.

The operator confirms once. A 24-hour default is not arbitrary: clients renew
at half the lease, so a KyDNS outage has roughly twelve hours before anything
actually loses its address. That is the mitigation for a single-node DHCP
server, and it is why failover is not a prerequisite for shipping this.

Then the rogue probe runs. Clear, and it enables.

## Operator surface

A **DHCP** tab holding the toggle, the six fields, and a live lease table of
MAC, IP, name, expiry, and a `Reserve` action. Unavailable deployments render
the reason in place of the form.

The JSON API and the CLI get the same settings and a read-only lease listing,
matching how every other setting is already exposed in all three places.

## Security notes

For `SECURITY.md`: KyDNS moves from reading DHCP leases as untrusted
configuration input to parsing packets from any device on the segment.

- Malformed packets are dropped, never fatal. They are deliberately **not**
  counted: a tally of unparseable broadcasts on a shared segment is not
  something an operator acts on, and the property that matters — a bad packet
  cannot take the server down — does not depend on counting them.
  `GET /api/v1/stats` already aggregates the other operational counters, and
  is where a drop counter would go if that judgement ever changes.
- The lease table is bounded by the range size by construction.
- Packet contents are not logged at default verbosity; MACs and hostnames
  are identifying.
- Option 12 handling is covered under "Names" above.

## Testing

| Area | Approach |
|---|---|
| Allocation | Table tests against a fake clock and an in-memory store: reservation wins, renewal, requested-IP, lowest-free, exhaustion, quarantine expiry. |
| Packets | Build DISCOVER/REQUEST/DECLINE/RELEASE/INFORM with `dhcpv4` and assert OFFER/ACK/NAK contents over an in-process conn. No real sockets. |
| Persistence | Leases survive a simulated restart; an unexpired lease is not re-issued to a second MAC. |
| Names | Two MACs claiming one hostname: second gets an address and no name. A lease cannot shadow a service. |
| Rogue probe | A fake responder on a loopback conn; assert refusal, the override path, and that the periodic probe warns without disabling. |
| Reservations | Zero, one, and two in-subnet addresses; MAC normalization and uniqueness. |
| Replication | A replica with `dhcp.enabled` does not bind; promotion binds. |
| Source contract | The existing `dhcp.Source` tests, run against `dhcpd.Server`. |
| Poller | `SetSource` swaps live, and the snapshot rebuilds. |

## Documentation

- `README.md` — DHCP moves into "What works today" with its deployment
  constraint; `dhcp_lease_file` moves off the restart-required list.
- `DESGINE.md` — `internal/dhcpd` joins the system shape.
- `SECURITY.md` — the note above.
- `2026-08-13-kydns-settings-in-the-ui-design.md` — the restart-list change.
