# Task 7 report — Packet handling

## Note on the brief file

`.superpowers/sdd/2026-08-19-kydns-builtin-dhcp-part1/task-7-brief.md` did not exist in the
worktree — only tasks 1–6 have brief/report files there. The equivalent content (identical in
substance: files, interfaces, all 8 steps, the full `server_test.go` and `server.go` source, the
commit message) is present verbatim in the plan document at
`docs/superpowers/plans/2026-08-19-kydns-builtin-dhcp-part1.md:1701-2480` ("### Task 7: Packet
handling"). I used that section as the brief rather than guessing or reconstructing one, and
cross-checked it against `progress.md`'s "Task 7 dependency" section, which independently
confirms the same API surface. No content was invented.

## What was changed

- `internal/dhcpd/server.go` (new) — `Server`, `Options`, `LeaseStore` interface, `New`,
  `Start`/`Stop`, `restore`, `handle` and the per-message-type handlers (`offer`, `ack`,
  `allocate`, `reply`, `nak`, `inform`, `send`), plus `normalizeMAC` and `sanitizeHostname`.
  Implements `discovery/dhcp.Source` (`Leases`, `Name`), asserted at compile time with
  `var _ idhcp.Source = (*Server)(nil)`.
- `internal/dhcpd/server_test.go` (new) — packet-path tests driving `handle()` against a fake
  `net.PacketConn` (`captureConn`) and a fake `LeaseStore` (`memStore`); hostname sanitizer table
  test.
- `go.mod` / `go.sum` — added `github.com/insomniacslk/dhcp v0.0.0-20260728151720-c308df0fdcef`
  (pinned, as instructed) plus its transitive deps (`u-root/uio`, `josharian/native`,
  `pierrec/lz4/v4`) via `go mod tidy`.

Both files were written in one pass matching the brief's Steps 2–5 content, with the Step 7
compile-time assertion included from the start (rather than added after an intermediate build) —
functionally identical end state, no behavior difference.

## Commands run and output

- `go get github.com/insomniacslk/dhcp@v0.0.0-20260728151720-c308df0fdcef` → `go: added
  github.com/insomniacslk/dhcp v0.0.0-20260728151720-c308df0fdcef`
- `go doc github.com/insomniacslk/dhcp/dhcpv4 NewReplyFromRequest` → signature matches exactly.
- `go doc github.com/insomniacslk/dhcp/dhcpv4` (full listing) → confirmed all `With*` modifiers
  (`WithMessageType`, `WithYourIP`, `WithServerIP`, `WithOption`, …) and all `Opt*` constructors
  (`OptSubnetMask`, `OptIPAddressLeaseTime`, `OptServerIdentifier`, `OptRouter`, `OptDNS`,
  `OptDomainName`, `OptHostName`, `OptMessageType`, `OptRequestedIPAddress`), and
  `FromBytes`/`New`/`NewDiscovery`.
- `go doc -all github.com/insomniacslk/dhcp/dhcpv4.DHCPv4` → confirmed accessor methods
  (`MessageType`, `HostName`, `RequestedIPAddress`, `ServerIdentifier`, `Router`, `DNS`,
  `DomainName`, `IPAddressLeaseTime`, `UpdateOption`, `ToBytes`) and fields `YourIPAddr`,
  `ClientHWAddr`.
- `go doc -all github.com/insomniacslk/dhcp/dhcpv4.MessageType` → confirmed all 8 message-type
  constants (`MessageTypeDiscover` through `MessageTypeInform`).
- `go doc github.com/insomniacslk/dhcp/dhcpv4/server4 NewServer` /  `Handler` → both match exactly.
- Every name the brief used was verified before writing `server.go`; nothing needed adjusting.
- `go mod tidy` → clean, only the expected new dependency lines.
- `go build ./...` → no output (success).
- `go test ./internal/dhcpd/ -v` → all 32 tests in the package PASS, including all 12 new
  server_test.go tests (`TestDiscoverGetsAnOfferWithOurOptions`,
  `TestDiscoverDoesNotPersistALease`, `TestRequestGetsAnAckAndPersists`,
  `TestRequestForAnAddressWeDoNotControlIsNaked`, `TestReleaseFreesTheAddress`,
  `TestDeclineQuarantinesTheAddress`, `TestInformGetsOptionsAndNoAddress`,
  `TestSecondClaimOnAHostnameGetsNoName`, `TestLeasesImplementsTheDiscoverySource`,
  `TestMalformedPacketsAreDroppedNotFatal`, `TestSanitizeHostname`) plus all pre-existing tests
  from tasks 4–6.
- `go test ./internal/dhcpd/ -race -count=2` → `ok` (1.015s), no race reported.
- `go vet ./internal/dhcpd/` → no output.
- `gofmt -l internal/dhcpd/` → no output (nothing unformatted).
- `go mod tidy` (re-run) → `git diff --stat` shows only `go.mod`/`go.sum`, no other diff.
- `go build ./...` (repo-wide, final check) → no output.

## Ambiguities / deviations from the brief

None in the code itself — the plan document's Task 7 section was implemented as written, and
every `go doc` check matched what it claimed with zero adjustment needed. The only deviation is
procedural: the brief file the dispatch message pointed at didn't exist as a standalone file, so
I sourced identical content from the plan document instead (see note above) rather than
guessing or asking to be re-dispatched.

## What I deliberately left alone

- The known minor from `progress.md`'s Task 7 self-consistency note — the comment in `allocate`
  says "A renewal or a reservation is not probed" but the code only gates on `!commit`, so an
  OFFER always probes regardless of whether it's a genuinely new address. This was already flagged
  as a deferred minor (comment vs. behavior, not a functional bug) before I started; I kept the
  brief's exact wording rather than rewriting the comment, since the brief is the reviewed source
  of truth and the ledger recorded this as accepted-as-is.
- No `Reconfigure` method — per ruling R5, not part of this package's surface.
- No per-host options, PXE, relay/`giaddr`, option 82, vendor classes, DHCPv6, or raw sockets —
  none of that appears anywhere in `server.go`, matching the global constraints.

## Fix round 1 — review findings

### FINDING 1 (Critical) — a bare DISCOVER committed a full-length lease and a name

Fixed as prescribed, in two parts:

**a) `internal/dhcpd/alloc.go`** — `Allocator.Allocate` gained a fourth parameter,
`ttl time.Duration`, and the `commit` closure now writes `Expires: now.Add(ttl)` instead of
`now.Add(a.cfg.LeaseTime)`. `Config.LeaseTime` is untouched as a field (still the ACK-path default,
supplied by the caller); the allocator itself no longer reads it directly.

Every existing call site in `internal/dhcpd/alloc_test.go` (28 call sites across 20 tests) passes
`24*time.Hour` — the allocator-level tests exercise what used to be the only behavior, i.e. a full
commit, so they now say so explicitly rather than relying on a hidden default. I did this
mechanically with a small Python script that finds each `a.Allocate(...)` call, matches the balanced
closing paren (three of the calls sit inside an `if _, ok := a.Allocate(...); ...` and don't end the
line), and inserts `, 24*time.Hour` before it — then diffed the result by hand to confirm all ~28
sites picked up the same value and nothing else moved.

**b) `internal/dhcpd/server.go`** — added `const offerHold = 60 * time.Second`. `allocate(mac, m,
commit)` now only computes a hostname and consults `NameTaken` when `commit` is true (the ACK path);
on the OFFER path (`commit == false`) `hostname` stays `""` and `ttl` stays `offerHold`, so
`NameTaken` is never called for an OFFER at all, per the instruction to drop it rather than compute
and discard. The probe-hit retry (`s.opts.Alloc.Allocate(mac, hostname, netip.Addr{}, ttl)`) now
also carries the ttl explicitly, so a retried OFFER still only holds for offerHold.

Tests added (`internal/dhcpd/server_test.go`), one per item in the review's list:
- `TestDiscoverNeverAppearsInLeases` — a DISCOVER with a hostname, never followed by a REQUEST,
  produces `s.Leases()` of length 0.
- `TestDiscoverHoldExpiresAndAddressBecomesAllocatable` — via a new `newTestServerWithClock` helper
  (a `newTestServer` variant with a mutable clock shared between `Options.Now` and the allocator's
  `now`), a DISCOVER's offered address is re-offered to a different MAC once the clock advances past
  `offerHold`.
- `TestDiscoverHostnameIsNotClaimed` — a DISCOVER for "laptop" from one MAC, then a REQUEST for the
  same name from a different MAC: the REQUESTing client gets an ACK and the stored lease carries the
  name; nothing about the first MAC's DISCOVER blocked it.
- `TestAckGrantsTheFullLeaseTerm` — a REQUEST's persisted `ExpiresAt` equals `epoch.Add(24 *
  time.Hour).Unix()`, i.e. `Cfg.LeaseTime`, not `offerHold`.

### FINDING 2 (Important) — Start/Stop leaked a goroutine and mislogged every clean stop

Fixed as prescribed. `Server` gained a `cancel context.CancelFunc` field alongside `srv`, guarded by
the same `mu`. `Start` now derives `runCtx, cancel := context.WithCancel(ctx)`, stores `cancel`, and
both goroutines watch/check `runCtx` instead of the caller's `ctx`. `Stop` reads and clears both
`srv` and `cancel` under the lock, then calls `cancel()` *before* `srv.Close()`, and is safe to call
when both are already nil (a second call from either an admin action or the watcher goroutine that
`Start` itself launches is a no-op).

Test added: `TestStopCancelsAndIsIdempotent`. It does not call `Start` — `server4.NewServer` binds a
real UDP socket, which the original task brief's global constraint ("No test may open a real
socket") forbids, and that constraint still applies to this fix round. Instead it constructs a
`Server` via the existing `newTestServer` helper, sets `s.cancel` directly to a closure that flips a
bool and calls a real `context.CancelFunc`, and asserts: `Stop()` calls it, the context it controls
is done afterward, and a second `Stop()` call is also error-free. This is a direct test of the
defect described (cancel not being invoked at all) and of the idempotency requirement; it does not
exercise the live `Serve()`/`Close()` interleaving, which the codebase's existing test strategy for
this package deliberately keeps out of reach of a unit test. That interleaving is now correct by
construction — `cancel()` happens synchronously inside `Stop` before `srv.Close()` is reached, so by
the time `Close` unblocks `Serve`'s read, `runCtx.Err()` is already non-nil — and is otherwise
covered by `go vet` and `-race`.

### FINDING 3 (Minor) — the probe-hit branch had no test

Added `stubProber` (`internal/dhcpd/server_test.go`), which reports exactly one address as in use.

- `TestProbeHitSkipsToTheNextAddressAndQuarantines` — a DISCOVER for a MAC gets an OFFER for an
  address other than the one `stubProber` reports as in use, and a follow-up direct
  `s.opts.Alloc.Allocate` call for a different MAC requesting the probed address by name does not
  get it back, confirming the quarantine (not just a one-time skip).
- `TestProbeHitWithNoFallbackAddressDrawsNoReply` — a one-address pool (`cfg.End = cfg.Start`) whose
  only address is the one `stubProber` reports in use: the retry after quarantine has nothing left
  to allocate, `allocate` returns `ok = false`, and `offer` sends no reply at all (asserted via
  `captureConn`, not by inspecting an OFFER's contents).

### FINDING 4 (Minor) — `normalizeMAC` should parse, not just lowercase

`normalizeMAC` now trims, then tries `net.ParseMAC`, and returns `HardwareAddr.String()` (which is
always the canonical lowercase colon-separated form) on success; on a parse error it falls back to
the trimmed input lowercased, exactly as before. Verified with a throwaway program
(`go doc`-style probe, not committed) that `net.ParseMAC` accepts colon, dash, and Cisco
dot-quad-hex forms and normalizes all three to the same colon form, and that it rejects
single-hex-digit octets (`"a:b:c:d:e:f"`) and non-MAC strings outright rather than padding them —
the test table reflects that: unparseable input round-trips through the lowercase fallback
unchanged.

Test added: `TestNormalizeMAC`, a table covering upper-case colon form, dash form, Cisco dot form,
leading/trailing whitespace, an unparseable-but-already-lowercase string, and the empty string.

## Commands run and output (fix round 1)

- `go build ./...` → no output.
- `go test ./internal/dhcpd/ -v` → all 40 tests PASS (32 pre-existing + 8 new:
  `TestDiscoverNeverAppearsInLeases`, `TestDiscoverHoldExpiresAndAddressBecomesAllocatable`,
  `TestDiscoverHostnameIsNotClaimed`, `TestAckGrantsTheFullLeaseTerm`,
  `TestProbeHitSkipsToTheNextAddressAndQuarantines`, `TestProbeHitWithNoFallbackAddressDrawsNoReply`,
  `TestNormalizeMAC`, `TestStopCancelsAndIsIdempotent`).
- `go test ./internal/dhcpd/ -race -count=2` → `ok` (1.015s), no race reported.
- `go vet ./internal/dhcpd/` → no output.
- `gofmt -l internal/dhcpd/` → no output.
- All 20 pre-existing allocator tests in `alloc_test.go` still pass with the new `ttl` argument
  (confirmed in the `-v` run above); no allocator test's expected behavior changed, only its call
  signature.

## Commit

`e59d9bb` (initial implementation) plus a second commit for this fix round; see the SHA reported to
the coordinator.

## Fix round 2 — R18: a tentative hold must never weaken a lease

### The defect fixed

Fix round 1 routed the OFFER path into `Allocator.Allocate` with `hostname == ""` and
`ttl == offerHold`. Allocation rules 1 and 2 both route a client that already holds an address
straight into `commit`, which wrote the lease unconditionally — so a bare DISCOVER from a MAC that
already held a full, named lease rewrote that lease to no name and 60 seconds: the victim's A record
vanished from `Server.Leases()` at once, and 60 s later its address was ACKed to a different client.

### What changed

`internal/dhcpd/alloc.go`
- The old `Allocate` body is now the private
  `allocate(mac, hostname string, requested netip.Addr, ttl time.Duration, tentative bool)`.
- `Allocate(mac, hostname, requested, ttl)` delegates with `tentative=false`. Signature and behaviour
  unchanged; every existing call site is untouched.
- New `Offer(mac string, requested netip.Addr, hold time.Duration) (Lease, bool)` delegates with
  `hostname=""`, `tentative=true`.
- Inside `commit`, the previous lease lookup is hoisted (`prev, hasPrev := a.byMAC[mac]`) and, when
  the call is tentative and the client already holds this same IP on a *live* lease, the previous
  `Hostname` is carried forward and the later of the two `Expires` is kept. The guard sits in
  `commit`, so it covers rule 1 (reservation) as well as rule 2 (renew) — gating rule 2 alone would
  have left a reserved client's name strippable.
- The `prev.Expires.After(now)` condition is deliberate: an *expired* lease is not one the client
  holds, so a tentative hold on it must not resurrect its name into `Leases()` for 60 s.

`internal/dhcpd/server.go`
- `(*Server).allocate` is split at the `commit` flag. The OFFER branch calls `Alloc.Offer`, including
  the post-probe retry; the ACK branch keeps calling `Alloc.Allocate` with `Cfg.LeaseTime` and the
  sanitized/arbitrated hostname. No guard on the ACK path: a REQUEST carrying no option 12 must still
  be able to clear a name, per the spec's "Names" section.
- No new exported API beyond `Offer`.

Tests added:
- `server_test.go`: `TestDiscoverDoesNotWeakenAnExistingLease`,
  `TestDiscoverDoesNotFreeAnExistingLeaseForAnotherClient`,
  `TestDiscoverDoesNotWeakenAReservedClientsLease`, `TestRequestWithNoHostnameClearsTheName`.
  All drive `handle()` against `captureConn`/`memStore`; no socket is opened.
- `alloc_test.go`: `TestOfferNeverWeakensALiveLease` — pins "later of the two expiries" in both
  directions (a hold longer than the remainder extends, a shorter one does not move it back) and the
  expired-lease case, which no handler-level test can reach (they all have 24 h ≫ 60 s).

### RED evidence

Tests written first and run against the unmodified `alloc.go`/`server.go`:

```
$ go test ./internal/dhcpd/ -count=1 -run 'TestDiscoverDoesNot|TestRequestWithNoHostnameClearsTheName' -v
=== RUN   TestDiscoverDoesNotPersistALease
--- PASS: TestDiscoverDoesNotPersistALease (0.00s)
=== RUN   TestDiscoverDoesNotWeakenAnExistingLease
    server_test.go:534: Leases returned 0 after a bare DISCOVER from the holder, want 1
--- FAIL: TestDiscoverDoesNotWeakenAnExistingLease (0.00s)
=== RUN   TestDiscoverDoesNotFreeAnExistingLeaseForAnotherClient
    server_test.go:563: acked 192.168.1.10 to a second client while the first still holds it
--- FAIL: TestDiscoverDoesNotFreeAnExistingLeaseForAnotherClient (0.00s)
=== RUN   TestDiscoverDoesNotWeakenAReservedClientsLease
    server_test.go:590: Leases returned 0 after a bare DISCOVER from the reserved client, want 1
--- FAIL: TestDiscoverDoesNotWeakenAReservedClientsLease (0.00s)
=== RUN   TestRequestWithNoHostnameClearsTheName
--- PASS: TestRequestWithNoHostnameClearsTheName (0.00s)
FAIL
FAIL	github.com/yoshiofthewire/kydns-server/internal/dhcpd	0.003s
```

Each failure is the reported harm, observed rather than argued:
- `Leases returned 0` — the DISCOVER blanked the victim's hostname, and `Leases()` filters unnamed
  leases out, so the A record was gone immediately.
- `acked 192.168.1.10 to a second client` — 61 s after the DISCOVER the victim's 60 s hold expired
  and its address was handed to another MAC: a duplicate address on the wire.
- The reservation variant fails identically, confirming rule 1 needs the guard as much as rule 2.
- `TestRequestWithNoHostnameClearsTheName` passes both before and after by design: it exists to fail
  if the guard is ever over-applied to the ACK path.

### GREEN evidence

```
$ go test ./internal/dhcpd/ -count=1 -v -run 'TestDiscover|TestRequestWithNoHostnameClearsTheName|TestNormalizeMAC|TestAckGrantsTheFullLeaseTerm|TestProbeHit'
--- PASS: TestDiscoverGetsAnOfferWithOurOptions (0.00s)
--- PASS: TestDiscoverDoesNotPersistALease (0.00s)
--- PASS: TestDiscoverNeverAppearsInLeases (0.00s)
--- PASS: TestDiscoverHoldExpiresAndAddressBecomesAllocatable (0.00s)
--- PASS: TestDiscoverHostnameIsNotClaimed (0.00s)
--- PASS: TestAckGrantsTheFullLeaseTerm (0.00s)
--- PASS: TestProbeHitSkipsToTheNextAddressAndQuarantines (0.00s)
--- PASS: TestProbeHitWithNoFallbackAddressDrawsNoReply (0.00s)
--- PASS: TestNormalizeMAC (0.00s)
--- PASS: TestDiscoverDoesNotWeakenAnExistingLease (0.00s)
--- PASS: TestDiscoverDoesNotFreeAnExistingLeaseForAnotherClient (0.00s)
--- PASS: TestDiscoverDoesNotWeakenAReservedClientsLease (0.00s)
--- PASS: TestRequestWithNoHostnameClearsTheName (0.00s)
PASS
ok  	github.com/yoshiofthewire/kydns-server/internal/dhcpd	0.003s

$ go test ./internal/dhcpd/ -count=1 -run TestOfferNeverWeakensALiveLease -v
--- PASS: TestOfferNeverWeakensALiveLease (0.00s)
ok  	github.com/yoshiofthewire/kydns-server/internal/dhcpd	0.003s
```

The four fix-round-1 tests that guard the original Critical all still pass, including
`TestDiscoverHoldExpiresAndAddressBecomesAllocatable` — its MAC holds nothing, so the guard
correctly does not apply to it.

### Full verification

```
$ go build ./...              → BUILD_OK (no output)
$ go vet ./...                → VET_OK (no output)
$ gofmt -l internal/dhcpd/    → FMT_CLEAN (no output)
$ go test ./internal/dhcpd/ -count=1        → ok  0.003s
$ go test ./internal/dhcpd/ -race -count=2  → ok  1.013s
$ go test ./... -count=1                    → 19 packages, all ok, 0 FAIL
```

### Concerns (not fixed here — outside R18, and pre-existing)

1. **The conflict probe defeats this fix in production, for renewals.** `(*Server).allocate`'s OFFER
   branch probes every offered address, including one the client already holds. The real `Prober`
   does ARP/ICMP, so a live client renewing by DISCOVER (normal after a reboot) answers its own
   probe: `Quarantine(l.IP)` plus `Alloc.Release(mac)` then destroy the very lease R18 protects and
   move the client to a different address. The behaviour predates fix round 2 and is unchanged by it,
   but it means the new tests only hold under `nopProber`. Both the design spec ("Before offering an
   address that is new to us — not a renewal, not a reservation") and the code's own comment say
   renewals must not be probed, so the code contradicts both. The smallest fix is to record the
   client's currently held address before calling `Offer` and skip the probe when the offered address
   equals it — I did not apply it because it changes probe semantics, which R18 does not cover and a
   scoped re-review is already scheduled.
2. **Rule 1 can still evict a *different* client's live lease on a mere DISCOVER.** The reservation
   rule commits without a freeness check, and `commit` deletes whatever other MAC holds that IP. R18's
   guard is scoped to "the client already holds", so it does not cover this. It is pre-existing, is
   arguably correct for an ACK (a reservation wins), and is unreachable in Part 1 because
   `SetReservations` is only ever called with an empty map — but on the OFFER path a forged DISCOVER
   from a reserved MAC would drop another client's name from DNS.

## Fix round 3 — ruling R19: the conflict probe runs only for an address new to the client

Fixes concern 1 of fix round 2: the spec ("Before offering an address that is new to us — not a
renewal, not a reservation") and `server.go`'s own comment both said renewals and reservations are
not probed, but the code probed every OFFER. A live client that DISCOVERs (NetworkManager restart,
wifi re-association, VM resume) answers the ARP probe of its own address, and the probe-hit branch
then quarantined that address for 10 minutes and released the lease.

### What changed

- `internal/dhcpd/alloc.go` — `Offer` now reports which rule fired:
  `Offer(mac string, requested netip.Addr, hold time.Duration) (l Lease, fresh, ok bool)`. `fresh`
  is true only for rule 3 (a requested address that is free) and rule 4 (lowest free in range);
  false for rule 1 (reservation) and rule 2 (renewal). The unexported `allocate` and its `commit`
  closure carry the flag; `Allocate` discards it and is unchanged externally — the ACK path never
  probes. Only the allocator knows which rule fired, which is why the server cannot derive this
  itself (comparing the offered address against the one the MAC holds would miss rule 1).
- `internal/dhcpd/server.go` — the OFFER branch probes only `if fresh && s.opts.Prober.InUse(l.IP)`.
  The probe-hit body is unchanged in substance (quarantine, release, one retry). The comment now
  describes what the code does.
- `internal/dhcpd/server_test.go` — two new tests plus one existing test de-blinded (below).
- `internal/dhcpd/alloc_test.go` — one new test; three call sites in
  `TestOfferNeverWeakensALiveLease` updated for the new arity (`got, _, ok :=`).

No exported API beyond the `Offer` signature. No `Reconfigure`.

### RED

Stage 1 — the two new server tests plus `TestDiscoverDoesNotFreeAnExistingLeaseForAnotherClient`,
which round 2 left prober-blind and which now points at `stubProber{inUse: victim}` (one line, no
change to what it asserts). All three compile against HEAD `b5e773d` and fail there:

```
$ go test ./internal/dhcpd/ -count=1 -run 'TestDiscoverDoesNotProbe...|TestDiscoverDoesNotFreeAnExistingLeaseForAnotherClient' -v
=== RUN   TestDiscoverDoesNotFreeAnExistingLeaseForAnotherClient
    server_test.go:575: leases = [{MAC:bb:bb:bb:bb:bb:bb IP:192.168.1.11 Hostname:other Expires:2026-08-20 12:01:01 +0000 UTC}], want the first client still holding laptop at 192.168.1.10
--- FAIL: TestDiscoverDoesNotFreeAnExistingLeaseForAnotherClient (0.00s)
=== RUN   TestDiscoverDoesNotProbeAnAddressTheClientAlreadyHolds
    server_test.go:640: offered 192.168.1.11, want the address the client already holds, 192.168.1.10
--- FAIL: TestDiscoverDoesNotProbeAnAddressTheClientAlreadyHolds (0.00s)
=== RUN   TestDiscoverDoesNotProbeAReservedClientsAddress
    server_test.go:665: leases = [], want laptop still at the reserved 192.168.1.11
--- FAIL: TestDiscoverDoesNotProbeAReservedClientsAddress (0.00s)
FAIL	github.com/yoshiofthewire/kydns-server/internal/dhcpd	0.004s
```

Each failure is exactly the reported harm. The client held `.10` named laptop for 24h; the probe of
its own address quarantined `.10`, released the lease, and the retry landed it on `.11`, unnamed,
60s — so `Leases()` lost the laptop entry and the OFFER carried the wrong address. The reservation
variant shows `leases = []`: `Quarantine` does not gate rule 1, so the retry re-committed the same
`.11` but as an unnamed 60s hold, which `Server.Leases` drops.

Stage 2 — `TestOfferReportsWhetherTheAddressIsNewToTheClient` cannot compile against HEAD, which is
the point of the ruling: the information does not exist there.

```
$ go test ./internal/dhcpd/ -count=1
internal/dhcpd/alloc_test.go:351:18: assignment mismatch: 3 variables but a.Offer returns 2 values
internal/dhcpd/alloc_test.go:356:19: assignment mismatch: 3 variables but a.Offer returns 2 values
internal/dhcpd/alloc_test.go:361:17: assignment mismatch: 3 variables but a.Offer returns 2 values
internal/dhcpd/alloc_test.go:368:17: assignment mismatch: 3 variables but a.Offer returns 2 values
FAIL	github.com/yoshiofthewire/kydns-server/internal/dhcpd [build failed]
```

### GREEN

```
$ go test ./internal/dhcpd/ -count=1 -run '<the new tests, the round-1, round-2 and probe tests>' -v
--- PASS: TestOfferNeverWeakensALiveLease (0.00s)
--- PASS: TestOfferReportsWhetherTheAddressIsNewToTheClient (0.00s)
--- PASS: TestDiscoverDoesNotPersistALease (0.00s)
--- PASS: TestDiscoverNeverAppearsInLeases (0.00s)
--- PASS: TestDiscoverHoldExpiresAndAddressBecomesAllocatable (0.00s)
--- PASS: TestDiscoverHostnameIsNotClaimed (0.00s)
--- PASS: TestProbeHitSkipsToTheNextAddressAndQuarantines (0.00s)
--- PASS: TestProbeHitWithNoFallbackAddressDrawsNoReply (0.00s)
--- PASS: TestNormalizeMAC (0.00s)
--- PASS: TestDiscoverDoesNotWeakenAnExistingLease (0.00s)
--- PASS: TestDiscoverDoesNotFreeAnExistingLeaseForAnotherClient (0.00s)
--- PASS: TestDiscoverDoesNotWeakenAReservedClientsLease (0.00s)
--- PASS: TestRequestWithNoHostnameClearsTheName (0.00s)
--- PASS: TestDiscoverDoesNotProbeAnAddressTheClientAlreadyHolds (0.00s)
--- PASS: TestDiscoverDoesNotProbeAReservedClientsAddress (0.00s)
ok  	github.com/yoshiofthewire/kydns-server/internal/dhcpd	0.005s
```

Both probe-hit tests still pass: their MAC holds nothing, so rules 3/4 fire, `fresh` is true, and
the probe still skips and quarantines. The gate is not over-applied.

### Full verification

```
$ go build ./...              → BUILD_OK (no output)
$ go vet ./...                → VET_OK (no output)
$ gofmt -l internal/dhcpd/    → FMT_CLEAN (no output)
$ go test ./internal/dhcpd/ -count=1        → ok  0.003s (54 tests, all PASS)
$ go test ./internal/dhcpd/ -race -count=2  → ok  1.015s
$ go test ./... -count=1                    → 19 packages, all ok, 0 FAIL
```

### Concerns

1. `TestDiscoverDoesNotProbeAReservedClientsAddress` reads `s.opts.Alloc.quarantine` directly to
   assert the reserved address was not quarantined. Observing it through `Allocate` is not possible:
   rule 1 ignores the quarantine list (the out-of-scope Part 2 item), so a quarantined reservation is
   still handed out. Same-package test, no lock needed (single goroutine), but it is white-box.
2. Not fixed, recorded already and unchanged by this round: `Quarantine` does not gate rule 1; the
   round-2 guard requires `prev.IP == ip`; rule 1 commits without a freeness check. Gating the probe
   on `fresh` makes the first unreachable from the probe path, which was the only way Part 1 could
   reach it.

## Fix round 4 — two probe-gate findings

### Finding A — an expired holding is new to us again

`internal/dhcpd/alloc.go`, rule 2 ("renew what this client already holds") called `commit(l.IP,
false)` unconditionally. There is no lease reaper — `byMAC` entries are pruned only by `restore()`
at boot — so a departed client's entry can outlive its own `Expires` indefinitely. Round 3 made
`fresh=false` mean "skip the probe", so once that entry was stale, a bare DISCOVER from the old MAC
was re-offered that address unprobed even if a static device had since taken it.

**Fix**, one line:

```go
// 2. Renew what this client already holds, if it is still ours to give.
if l, ok := a.byMAC[mac]; ok && a.usable(l.IP) && a.reservedIP[l.IP] == "" {
	return commit(l.IP, !l.Expires.After(now)) // an expired holding is new to us again
}
```

`fresh` is now true only when the held lease has expired — a live renewal is still unprobed, per
the spec.

Test added: `TestDiscoverProbesAnExpiredHoldingsAddress` (`server_test.go`). A client REQUESTs and
gets a full 24h lease; the clock advances 24h+1s past `Expires`; a prober is installed reporting
that address in use; a bare DISCOVER from the same MAC arrives. Assertion: the OFFER is not that
address (with a 3-address pool, the fallback to rule 4 has room).

RED, against HEAD `f68d07b` (the one-line fix reverted via `git stash`, test unchanged):

```
$ go test ./internal/dhcpd/ -run TestDiscoverProbesAnExpiredHoldingsAddress -v -count=1
=== RUN   TestDiscoverProbesAnExpiredHoldingsAddress
    server_test.go:695: offered 192.168.1.10, the expired holding a static device now answers a probe for
--- FAIL: TestDiscoverProbesAnExpiredHoldingsAddress (0.00s)
FAIL
```

GREEN, with the fix restored:

```
$ go test ./internal/dhcpd/ -run TestDiscoverProbesAnExpiredHoldingsAddress -v -count=1
--- PASS: TestDiscoverProbesAnExpiredHoldingsAddress (0.00s)
ok
```

### Finding B — no server-path test covers rule 3

Both existing probe tests drive a bare DISCOVER (no option 50), so they exercise rule 4 only. Rule
3 — a DISCOVER carrying option 50 for a free address the prober reports in use — was covered at the
allocator layer (`TestOfferReportsWhetherTheAddressIsNewToTheClient`) but not at the packet layer,
so a mutation mislabeling rule 3 as `fresh=false` would be invisible to `server_test.go`.

Test added: `TestProbeHitOnARequestedAddressSkipsAndQuarantines` (`server_test.go`). Builds the
DISCOVER with the existing `discover()` helper and adds `dhcpv4.OptRequestedIPAddress` for a free
address, matching how `request()` sets the same option — no new packet-building helper. A
`stubProber` reports the requested address in use. Asserts the OFFER is not that address, and that
a follow-up `Allocate` call for a different MAC requesting it by name does not get it back
(quarantine, not just a one-time skip) — same shape as `TestProbeHitSkipsToTheNextAddressAndQuarantines`.

This test passes against HEAD (a coverage gap, not a bug), so its power was checked by mutation:
temporarily changed rule 3's `commit(requested, true)` to `commit(requested, false)` in
`alloc.go`, ran the test, then reverted (`git diff` confirms `alloc.go` carries only the Finding A
fix afterward):

```
$ sed -i 's/return commit(requested, true)/return commit(requested, false)/' internal/dhcpd/alloc.go
$ go test ./internal/dhcpd/ -run TestProbeHitOnARequestedAddressSkipsAndQuarantines -v -count=1
=== RUN   TestProbeHitOnARequestedAddressSkipsAndQuarantines
    server_test.go:717: offered 192.168.1.11, the requested address the probe reported in use
--- FAIL: TestProbeHitOnARequestedAddressSkipsAndQuarantines (0.00s)
FAIL
$ sed -i 's/return commit(requested, false)/return commit(requested, true)/' internal/dhcpd/alloc.go
```

The test discriminates: it fails when rule 3 is mislabeled not-fresh, and passes when it is
correctly fresh.

### Full verification

```
$ go build ./...                            → BUILD_OK (no output)
$ go test ./internal/dhcpd/ -count=1        → ok (55 tests: 53 pre-existing + 2 new, all PASS)
$ go test ./internal/dhcpd/ -race -count=2  → ok 1.014s, no race reported
$ go test ./... -count=1                    → 19 packages, all ok, 0 FAIL
$ go vet ./...                              → VET_OK (no output)
$ gofmt -l internal/dhcpd/                  → FMT_CLEAN (no output)
```

Scope held to `internal/dhcpd/alloc.go` and `internal/dhcpd/server_test.go`; `alloc_test.go` was
not touched — no new unit-level assertion was needed there, since both findings are only visible
through the server path (`Server.allocate`'s `fresh &&` gate), which is exactly what round 4 was
asked to close.

### Concerns

None. Both findings are closed; no new deferred items. Round 2's concern 2 (rule 1 can evict
another client's live lease on a mere DISCOVER, unreachable in Part 1 since `SetReservations` is
only ever called with an empty map) remains open and out of scope for this round.
