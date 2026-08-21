# Whole-branch review findings — fix wave

Base 7dc7027, head 64616a0. Every item below was demonstrated by the reviewer, not inferred.

## C1 (Critical) — one unauthenticated DHCPDECLINE destroys any client's lease

`internal/dhcpd/server.go:194-203` and `internal/dhcpd/alloc.go:165-173`.

`Decline(ip)` deletes whichever MAC holds `ip` without ever checking that it is the MAC that sent
the packet, and writes `quarantine[ip]` with no range check at all. Demonstrated:

    before: 1 lease(s), victim holds 192.168.1.100 as "nas"
    after one spoofed DECLINE: 0 lease(s)

One broadcast UDP packet to port 67, from any MAC, naming any address. The victim's DNS name
disappears from `Leases()` immediately, its address is held out of the pool for ten minutes, and when
the victim renews it is handed a different address. Range-many packets take the whole segment down for
ten minutes and delete every DHCP-derived name. This is byte-for-byte the harm ruling R18 rated
Critical, reached through a packet type R15/R18/R19 never revisited.

Second half: the quarantine map is attacker-fed and unbounded. 1,000 declines for out-of-pool
addresses left 1,000 entries, and nothing prunes expired ones. That contradicts the spec's
"The lease table is bounded by the range size by construction."

Fix: `Decline(mac string, ip netip.Addr)` — quarantine only when `a.inRange(ip)`, and delete the lease
only when `a.byIP[ip] == mac`. That keeps the spec's stated behaviour for the legitimate case, which is
the only case RFC 2131 describes.

## C2 (Critical) — the rogue probe cannot see a DHCP server on this host, and the bind will not stop it

`internal/dhcpd/rogue.go:143`, reached from `internal/app/dhcp.go:124`.

`collectForeign` drops any OFFER whose server identifier equals `self` (= `info.Addr`, our own address
on the interface). dnsmasq, ISC dhcpd and systemd-networkd all set option 54 to the address of the
interface they answered on — which, for a server co-resident with KyDNS, is our address. So its OFFER
is filtered out as "ours" and `build()` reports clear.

In Part 1 the filter is pure downside: `Reconcile` runs `stopLocked()` at `app/dhcp.go:62` before every
`build()`, so our own listener is never running when the probe fires. The filter can only ever suppress
somebody else on our host.

The `:67` bind is not a backstop. `server4.NewIPv4UDPConn` sets `SO_REUSEADDR` and `SO_REUSEPORT`.
Measured on this kernel:

    dnsmasq-style REUSEADDR, then kydns REUSEADDR+REUSEPORT: SECOND BIND SUCCEEDED -> two DHCP servers on one host
    no options, then REUSEADDR+REUSEPORT: second bind refused (Address already in use)

DISCOVERs are broadcast, so Linux delivers each to both sockets and both servers answer. That is the
failure the spec's decision table calls "the one failure that ruins an evening", on the deployment this
feature most directly competes with — a Pi-hole-shaped box already running dnsmasq DHCP.

Fix: pass `netip.Addr{}` as `self` from `app/dhcp.go:124` in Part 1, or gate the self-filter on "our own
listener is currently bound". Part 2's periodic probe is the only caller that needs the filter.

## I1 (Important) — Leases() returns map order into an order-sensitive digest

`internal/dhcpd/server.go:84-95` against `internal/discovery/poller.go:180-189`.

`Allocator.Leases()` ranges over `byMAC`. `digest` is a concatenation whose doc comment still says
"The parser emits a stable order" — true of the dnsmasq file source, false of this one. Measured with
six leases and no network activity:

    20 polls of an unchanged lease set produced 12 onChange (zone rebuild) calls

Each is three SQLite reads plus a full rebuild of every view index, plus an Info log line. It also fires
on every ACK, because `OnChange` calls `Poll` synchronously from the packet handler. Cross-task seam:
task 1 never saw a map-backed source, task 7 never saw the digest.

Fix: one `slices.SortFunc` on IP in `Server.Leases()`.

## I2 (Important) — the hostname check is not atomic with the commit

`internal/dhcpd/server.go:281-286`. `NameTaken` takes and releases the allocator lock, then `Allocate`
takes it again. `server4.Serve` runs `go s.Handler(...)` per packet, so two REQUESTs carrying the same
option 12 both see "free". Reproduced with four concurrent REQUESTs:

    2 leases hold the same client-chosen hostname at once

Combined with I1, `zone/snapshot.go:102` (`idx.Forward[name] = ...`, last write wins) makes the
published A record flap between the two addresses on every rebuild. Contradicts the spec's "Between two
leases, first claim wins for the life of that lease."

Fix: move the arbitration inside `allocate` under `a.mu`, or add `Allocator.ClaimName`.

## I3 (Important) — the rogue-refusal decision has no test and no seam to write one

`internal/app/dhcp.go:84-132`. `build()` calls package-level `dhcpd.Qualifies`, `dhcpd.Inspect` and
`dhcpd.DetectForeign` directly. The only "cannot start" test (`app/dhcp_test.go:113`) uses a nonexistent
interface, so it exits at `Qualifies`. The two branches that matter — foreign server found, and probe
errored (ruling R22) — are executed by nothing in the suite. `ForeignServerError` appears in no test
file. R22 was a deliberate, operator-visible policy call and it is currently held up by inspection alone.

Fix: three function fields on `dhcpRunner` defaulting to the real ones, and three tests. This is also
what C2 needs to be regression-proofed.

## I4 (Important) — a save that build rejects takes a working listener down for good

`internal/app/dhcp.go:62`. `dhcpConfigEqual` includes `PrivateDomain`, so renaming the private domain
stops the DHCP listener, runs a 2-second rogue probe with nothing bound, and rebuilds. Any transient
failure in that window — the interface flapping, the host's DHCP client grabbing `:68`, a neighbour's
server answering once — leaves the LAN with no DHCP server and no retry: `Reconcile` has exactly three
triggers (boot, settings save, promotion).

I had deferred this on the grounds that building first would make `DetectForeign` hear our own server.
C2 shows the self-filter should be removed here anyway, so the two are one fix: skip the rogue probe
entirely when the interface is unchanged and a listener is already running on it (the segment was
cleared when it started; the periodic probe is Part 2's job), and build before you stop.

## I5 (Important) — a REQUEST we cannot satisfy gets an ACK for a different address instead of a NAK

`internal/dhcpd/server.go:221-235`. The only NAK condition is "requested address is outside our subnet".
Demonstrated for an in-subnet, out-of-pool INIT-REBOOT request:

    client asked for 192.168.1.50 in INIT-REBOOT; server replied ACK yiaddr=192.168.1.100

`m.ClientIPAddr` appears nowhere in the package, so a RENEWING client (ciaddr set, no option 50) whose
lease we do not know is silently re-addressed rather than NAKed. That is precisely the promoted-replica
case, and the spec's Replication section states the opposite: "clients whose leases it does not know
will be NAKed and re-DISCOVER." RFC 2131 4.3.2 agrees.

Fix: if option 50 or `ciaddr` names an address and the allocator returns a different one, NAK.

## Small correctness items — fix in the same wave

- `internal/settings/validate.go:172` trims before parsing; `internal/app/dhcp.go:163-169` does not.
  `" 192.168.1.100"` saves green and then permanently refuses to start. Make the runner trim too.
- `internal/app/dhcp.go:143-147` silently drops a malformed `dhcp_secondary_dns`, in a function where
  every other bad value is a named error. The spec is explicit that turning DHCP on "must not silently
  undo" the two-resolver advice. Return a named error.
- `internal/web/serversettings.go:118` — when `liveSettings()` returns `ok == false`, all seven DHCP
  fields are written as zero and a running server is switched off. Abort the save instead of falling
  through.
- `internal/settings/validate.go:127,131,142,149,160` — field names are dotted (`dhcp.range_end`) while
  every wire and CLI key is snake_case and every neighbouring `bad()` call uses the wire name.
  `writeErr(..., fe.Field, ...)` hands the client a field it never sent. Use the wire names.
- `internal/dhcpd/rogue.go:138-143` — an OFFER with an explicit `0.0.0.0` in option 54 never reaches the
  source-address fallback and is reported as "a server at 0.0.0.0", at the exact moment the operator
  needs a name to act on. One `!id.IsUnspecified()`.
- `internal/app/dhcp.go:54` — the not-wanted branch clears `lastError`, so a replica with
  `dhcp_enabled=true` reports "running no" with no reason at all. Give the role refusal a stated reason.
- `internal/dhcpd/rogue_test.go` — `TestNewProbeDiscoveryAsksForABroadcastReply` asserts
  `m.IsBroadcast()`, a struct-field read. Assert the serialized byte instead (`ToBytes()` bytes 10-11).
  This is the guard on ruling R23, the highest-value catch in the branch; it should not be one level
  removed from what matters.
- `docs/superpowers/specs/2026-08-13-kydns-settings-in-the-ui-design.md:45` still heads `private_domain`
  "Requires a restart, and says so" while `:190` now says nothing produces that banner. `Apply` renames
  the zone live (`TestApplyRenamesTheZoneEverywhere`), so the heading is false. Delete it.
