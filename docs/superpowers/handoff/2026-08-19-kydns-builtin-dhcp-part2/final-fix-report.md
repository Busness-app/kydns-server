# Final fix wave — Part 2 whole-branch review findings

Base `070a52e`, branch `worktree-dhcp-part2`. Seven findings: three Important, four Minor.
All seven are fixed. One factual correction to the findings list is recorded under M2.

## I1 — a failed service read binds the listener with an empty reservation map

**Decision: refuse the build.**

The two shapes are not equivalent in outcome. Publishing a synthetic `ReservationProblem` and
starting anyway leaves the demonstrated failure intact — the listener still binds with an empty
map, and the first DISCOVER from an unrelated MAC still takes the reserved address. It only
annotates the wrong-address outcome; it does not prevent it. Refusing prevents it.

The cost the ruling weighed — a transient store hiccup taking DHCP down for the whole LAN — is
smaller than it looks on this path, for three reasons:

1. The refusal sits **after** the unchanged-config early return, so a save that changes nothing
   while a listener is already serving never reaches it. The armed allocator is untouched.
2. The refusal sits **before** `build`, and `build`-before-`stop` already guarantees a refusal
   leaves a running listener alone. Pinned by `TestASeedReadErrorLeavesTheRunningListenerAlone`.
3. What remains is a store error at boot, or on the save that changes the interface. Neither is
   transient in the way R22's probe failure is: the 1+N `ErrNotFound` race needs a concurrent
   registry delete, which needs an admin, and an admin is in front of the refusal to read it.

That leaves refusal consistent with every other refusal in `build` — none of which has an
automatic retry either — and the operator gets `lastError` on the DHCP tab naming the read that
failed, rather than "running, no problems" beside a mis-addressed service.

Changed, `internal/app/dhcp.go`:
- `Reconcile` reads the role once and passes it to `reconcile`, then reads the service list only
  when `dhcpWanted(v, role)`. Reading the role once is what makes the skip safe: two independent
  `d.role()` calls could disagree across a promotion and seed a *starting* listener with `nil`.
- `reconcile(v, role, svcs, svcErr)`; a non-nil `svcErr` goes to `d.fail` with
  `"could not read the service list to seed DHCP reservations, so refusing to start: %w"`.

Tests (`internal/app/dhcp_test.go`), covering both error branches, neither of which had one:
- `TestASeedReadErrorRefusesToStart` — no bind, `Status()` refused with a reason naming the read,
  no lease source published.
- `TestASeedReadErrorLeavesTheRunningListenerAlone` — rebuild path with a changed range; the
  listener and its allocator survive. It also pins `start`, so a regression fails the assertion
  instead of reaching for `:67`.
- `TestARefreshReadErrorLeavesTheArmedReservationsAlone` — the refresh branch: a failed read
  never republishes, so the armed reservation still resolves.
- `TestReconcileDoesNotReadTheServicesWhenDHCPIsOff` — pins the `dhcpWanted` skip.

**Mutation:** deleting the `svcErr` branch fails both seed tests
(`the listener bound with no reservations…` / `…replaced the running listener`). Deleting the
`return` after `RefreshReservations`' error log fails the refresh test
(`the reserved client got 192.168.1.100`). Killed.

## I2 — `ProbeForeign`'s composition was unpinned

`internal/dhcpd/server.go`: extracted
`(*Server).probeForeignWith(ctx, wait, dial) ([]Foreign, error)` returning
`detectForeign(ctx, wait, dial, s.ignoreXID)`; `ProbeForeign` calls it with
`probeConn(ctx, s.opts.Iface.Name)`. `internal/dhcpd/rogue_test.go`'s `segmentConn.probe` helper
now goes through it, so both existing tests execute the real pairing. Everything but the socket
call itself is now covered.

**Mutation:** `s.ignoreXID` → `nil` inside `probeForeignWith` fails both
`TestProbeForeignIgnoresOurOwnAnswer` (`probe = [192.168.1.5 (offering 192.168.1.10)] on a
segment whose only DHCP server is us`) and
`TestProbeForeignReportsACoResidentServerAtOurOwnAddress` (our own reply wins the ServerID dedupe
and hides the real server). Killed — this is the mutant that previously survived.

## I3 — SECURITY.md's "only" was false

`SECURITY.md`: added "an address that answered a conflict probe" to the enumeration of logged
exceptions, which is `internal/dhcpd/server.go`'s quarantine warning. Documentation; no test.

## M1 — the network and broadcast addresses were reservable

`internal/dhcpd/reserve.go`: in the `case 1` arm, a resolved address equal to
`subnet.Masked().Addr()` or to the subnet's last address becomes a `ReservationProblem` rather
than a reservation. New `broadcastOf(netip.Prefix)` computes the last IPv4 address of the prefix
and returns an invalid `Addr` for a non-v4 prefix, so it cannot panic on `As4`.

`internal/dhcpd/alloc.go` is untouched, as required.

Tests (`internal/dhcpd/reserve_test.go`):
- `TestReservationsRefuseTheNetworkAndBroadcastAddresses` — `.0` and `.255` in a `/24`.
- `TestReservationsAllowTheOctetEndsInsideAWiderSubnet` — `192.168.0.255` and `192.168.1.0` are
  ordinary usable addresses inside a `/23`. The rule is the subnet's ends, not the last octet.
  (This test caught my first draft, which had used `192.168.1.255` in a `/23` as the "usable"
  case — that address *is* that subnet's broadcast.)

**Mutation:** deleting the check fails the first test
(`192.168.1.0 was reserved as map[aa:bb:cc:dd:ee:ff:192.168.1.0]`). Killed.

## M2 — a comment contradicted the test beside it

**Correction to the finding.** The false "without zero-padding" claim exists in **one** place,
`internal/dhcpd/server.go`'s `normalizeMAC`, not two. `internal/registry/validate.go:98-110`
(`NormalizeMAC`) makes no zero-padding claim — it says only "lowercase, colon-separated, which is
what `net.HardwareAddr` renders" and that its body is identical to dhcpd's, both of which are
true. Nothing was changed there. Verified by `grep -rn "zero-padding\|dashes\|separators"` over
`internal/`, which returns exactly one hit in each of `server.go:452` and `:453`.

The rest of the finding checks out. Executed against Go's `net.ParseMAC`:

    "a:b:c:d:e:f"        -> err: invalid MAC address     (the false claim)
    "aabbccddeeff"       -> aa:bb:cc:dd:ee:ff            (the true claim)
    "AA-BB-CC-DD-EE-FF"  -> aa:bb:cc:dd:ee:ff
    "aabb.ccdd.eeff"     -> aa:bb:cc:dd:ee:ff

Deleted the four words and rewrapped. A test was not expected for a comment, and none was added
for the deletion — but the surviving "no separators at all" claim was itself unpinned, which is
the same defect class, so `{"AABBCCDDEEFF", "aa:bb:cc:dd:ee:ff"}` was added to `TestNormalizeMAC`
in **both** `internal/dhcpd/server_test.go` and `internal/registry/validate_test.go`, whose
tables are deliberately identical.

## M3 — the "override revoked" log could not fire if the override was granted while running

`internal/app/dhcp.go`: the unchanged-config early return now sets
`d.current.DHCPAllowForeign = v.DHCPAllowForeign` unconditionally, replacing the one-directional
`= false` inside the revocation branch. One assignment covers both transitions.

Test: `TestGrantingTheOverrideWhileRunningIsStillRecorded` — grant while running, then revoke;
the revocation must log. `TestRevokingTheOverrideWhileRunningSaysSo` (existing, including its
"once per transition" assertion) still passes unchanged.

**Mutation:** restoring the old `= false`-inside-the-branch form fails the new test
(`revoking an override granted while running logged nothing: ""`) and leaves the existing test
green — which is exactly why it needed a new test. Killed.

## M4 — Enter in the DHCP settings form ran the wizard

`internal/web/templates/dhcp.html`: the Save button moved to first-in-DOM, immediately after the
CSRF input, so implicit submission picks it rather than the `formaction="/dhcp/suggest"` button.

Implicit submission picks the *first* submit in the form, and the wizard button sits just under
the Interface field near the top — so Save has to go to the very top of the DOM, which would
also draw it there. `internal/web/static/app.css` gains `form.stack > button.last { order: 1; }`
and the button gains `class="last"`, so it is first in DOM and still drawn last on screen where
an operator looks for it. `order` applies to grid items, and `form.stack` is `display: grid`.

No test, as the finding expected. `dhcp.html` is the only template in the repo using
`formaction`, so this is not a pattern repeated elsewhere.

## Verification

    go build ./...                                                    clean
    go vet ./...                                                      clean
    gofmt -l internal/                                                clean (no output)
    go test ./internal/dhcpd/... ./internal/app/... ./internal/web/... ok, ok, ok
    go test ./internal/app/... ./internal/dhcpd/... -race -count=2     ok (60.1s, 1.0s)
    go test ./... -count=1                                            19 packages, 0 failures

Mutation discipline was applied to I1 (both branches, plus the refresh branch), I2, M1 and M3.
**No survivors.** M2 and M4 are a comment and a DOM reorder; no test was expected for either and
none was added for the change itself, though M2's surviving true claim was pinned as noted.

## Invariants held

- `internal/dhcpd/alloc.go` untouched — no allocation rule changed.
- A DISCOVER still cannot damage a lease; nothing on the packet path changed. The I1 fix moves in
  the safe direction: the window where an unarmed allocator answers is now closed rather than
  merely reported.
- `dhcpWanted`'s `role != RoleReplica` gate is byte-identical.
- No `dhcp_*` column added anywhere; no `ApplySnapshot` change.
- No new web route, so `TestEveryPostRouteRequiresSessionAndCSRF` has nothing new to sweep.
- No test opens a DHCP socket. `TestASeedReadErrorLeavesTheRunningListenerAlone` explicitly pins
  `start` so a regression cannot reach the real bind.

## Concerns

1. **I1 has no automatic retry.** That is inherited from every other `build` refusal, not
   introduced here, but it is the price of the decision: a store error at boot leaves DHCP down
   until a settings save. The tab says why. If that trade is judged wrong, the alternative is to
   have `RefreshReservations` — which already runs after every registry write — retry the build
   when `d.alloc == nil` and `d.lastError` is a seed error. That is a real behaviour change and
   was out of scope for this wave.
2. **M1 does not exclude the network/broadcast address from the `seen` set.** A service holding
   both `192.168.1.20` and `192.168.1.255` still reports "2 addresses inside the DHCP subnet"
   rather than resolving to `.20`. That is the existing never-guess behaviour and is left alone
   deliberately; the operator's fix is the same either way.
3. `broadcastOf` has no special case for a `/31` or `/32` DHCP subnet, where the network and
   broadcast concept does not apply. Such a subnet cannot serve DHCP at all — the range
   validation refuses first — so no reachable path is affected.
