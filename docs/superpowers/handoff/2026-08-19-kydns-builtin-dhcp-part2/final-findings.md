# Whole-branch review findings — fix wave (Part 2)

Base e0662c9, head 070a52e. No Critical. Everything below was demonstrated or traced, not inferred.

## I1 (Important) — a failed service read binds the listener with an empty reservation map, silently

`internal/app/dhcp.go:97-105` and `:143-144`.

`Reconcile` logs and continues when `d.services()` errors, so `reconcile` seeds `SetReservations({})`
and binds. The `RefreshReservations` that follows hits the same error and returns BEFORE touching
`d.problems`. Net result: the listener serves with no reservations, `Status()` reports running with no
error, `Problems()` is empty, and nothing retries until the next registry write or settings save.

This is exactly the hazard the comment at `dhcp.go:138-142` exists to prevent — "an allocator with no
reservations yet would hand a reserved address to whoever asked first". Reproduced by execution against
a scratch copy of HEAD:

    running=true err=<nil> problems=[] firstOffer=192.168.1.100 reserved=192.168.1.100

The first DISCOVER from an unrelated MAC was handed the reserved address. The service's A record then
points at a different device, with nothing on the DHCP tab to say so.

The trigger is not only a store failure. `store.Services()` is a 1+N read (`store.go:632-657`), so a
service deleted between the ID sweep and its per-ID read returns `ErrNotFound` — a concurrent delete
during a settings save reaches this path.

The asymmetry is what makes it a bug rather than a choice: `RefreshReservations` treats a read error as
SKIP (never publishes), while the seed treats it as EMPTY.

Fix: on a seed read error, either refuse the build — safest, and consistent with every other "the
operator must fix this first" refusal in `build` — or publish a single synthetic `ReservationProblem`
so the tab says reservations could not be loaded and the operator can retry. While there, move the read
below a `dhcpWanted` check so a DHCP-off node stops paying for it on every save. Neither error branch
has a test today.

## I2 (Important) — `ProbeForeign`'s composition is unpinned, and the periodic probe turns on it

`internal/dhcpd/server.go:75-77`.

Both tests call `detectForeign(..., c.srv.ignoreXID)` directly, so the pairing of
`probeConn(ctx, s.opts.Iface.Name)` with `s.ignoreXID` never executes. Mutating that argument to `nil`
leaves the suite green and reintroduces Part 1's exact defect: our own listener answers the probe, wins
`collectForeign`'s dedupe-by-ServerID, and both false-alarms the banner and masks a real co-resident
server.

This was a deferred minor (ledger :146). It is promoted because it is precisely the shape ruling P13
said must be closed rather than deferred — a guard correct today and unpinned.

Fix: extract `func (s *Server) probeForeignWith(ctx, wait, dial) ([]Foreign, error)` returning
`detectForeign(ctx, wait, dial, s.ignoreXID)`, have `ProbeForeign` call it with `probeConn(...)`, and
point the two existing tests at it. That pins everything except the socket call itself.

## I3 — deferred minor #8, promoted: SECURITY.md's "only" is false

`SECURITY.md:37-41` says "only the exceptions are" and enumerates six logs. `internal/dhcpd/server.go:350`
is a seventh — it logs an IP during ordinary packet handling when a probe hits.

This branch just spent a Critical (P20) on a security document describing software that did not ship.
Leaving a false "only" three sections above it is the same defect at smaller scale, at a cost of five
words. Add "an address that answered a conflict probe" to the enumeration.

## M1 (Minor) — the network and broadcast addresses are reservable

`internal/dhcpd/reserve.go:60`. `subnet.Contains` accepts `x.x.x.0` and `x.x.x.255`, and `protected`
(`alloc.go:301-303`) covers only Host and Gateway — so a service given `192.168.1.255` and a MAC gets it
handed out by rule 1. Operator-caused and admin-gated, but the resolver already refuses to guess in three
other places. Two lines and one more `ReservationProblem` reason.

## M2 (Minor) — two production comments contradict the tests beside them

`internal/dhcpd/server.go:443-447` and `internal/registry/validate.go:98-104` both claim a MAC "without
zero-padding ... still compares equal". It does not: `net.ParseMAC("a:b:c:d:e:f")` fails, the fallback
lowercases it unchanged, and the package's own test table says so at `server_test.go:511`. The behaviour
is safe — `ValidateMAC` rejects that form with a field-addressable 400 — but the comments are false.
The "no separators at all" claim IS true. Delete four words in each.

This is my error: ruling P4 asserted the unpadded case converges without testing it, and the claim
propagated into these two comments.

## M3 (Minor) — the "override revoked" log cannot fire if the override was granted while running

`internal/app/dhcp.go:117-124`. `dhcpConfigEqual` deliberately ignores `DHCPAllowForeign`, so granting it
returns early without updating `d.current`; the later revocation then sees `d.current.DHCPAllowForeign ==
false` and says nothing. Set the field in that early-return branch too.

## M4 (Minor) — Enter in the DHCP settings form runs the wizard instead of Save

`internal/web/templates/dhcp.html:65` puts the `formaction` button before Save at `:81`, so implicit
submission picks it and silently replaces a hand-typed range with the suggestion. Nothing is written, but
the operator's typing is. Move Save first in DOM order.

## Explicitly NOT in this wave

- `ack` NAKing after `allocate` has committed (`server.go:301-313`). Pre-existing from Part 1, amplified
  here, self-healing, and hoisting the check is a real behaviour change. Recorded.
- Promotion's `Reconcile` racing `Apply` for the poller's source (`serve.go:312` vs `apply.go:78-95`).
  Pre-existing, both admin-initiated, tiny window. Recorded.
- The replica pre-configuration spec contradiction. That is an operator decision, handled separately.
- No test reads `packaging/kydns.service` to pin the capability set. Recorded as the one untested safety
  property; worth a five-line content assertion at some point.
