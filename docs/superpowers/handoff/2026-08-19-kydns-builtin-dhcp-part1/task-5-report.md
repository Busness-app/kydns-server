# Task 5 report: the allocator

## Post-review fixes

Review came back: 22/23 rules pass, no Critical, two changes required before commit.

### Finding 1 (Important) — reservation path bypassed the host/gateway exclusion

`Allocate` case 1 committed a reservation without checking `usable()`, so a reservation naming
`cfg.Host` or `cfg.Gateway` would have been handed to a client, contradicting `Config`'s own doc
comment. Fixed exactly as directed:

- Split `protected(ip)` out of `usable()`: `ip == a.cfg.Host || ip == a.cfg.Gateway`.
- `usable()` is now `a.inRange(ip) && !a.protected(ip)`.
- Case 1 is now `if ip, ok := a.reserved[mac]; ok && !a.protected(ip) { return commit(ip) }` —
  no `inRange` check added, so a reservation outside the dynamic range still wins (pinned by the
  pre-existing `TestReservationWinsOverEverything`); only `protected` addresses fall through to
  renewal/requested/lowest-free.

Added `TestAReservedGatewayFallsBackToADynamicAddress` and
`TestAReservedHostFallsBackToADynamicAddress` in `internal/dhcpd/alloc_test.go`. Both reserve
`cfg.Gateway` / `cfg.Host` respectively for a MAC, call `Allocate`, and assert the client gets a
normal in-range address (`192.168.1.10`) rather than the protected one.

**Verified the tests actually catch the bug**, not just that they pass: stashed the `alloc.go`
fix (keeping the new tests) and reran the two new tests — both failed with the exact expected
message (`Allocate handed out the gateway 192.168.1.1 because a reservation named it` /
`...our own address 192.168.1.5...`). Restored the fix and reconfirmed both pass.

### Finding 2 (Minor) — no test for a MAC's address moving

Added two tests covering the `byMAC`/`byIP` consistency case the reviewer flagged as
hand-traced-only:

- `TestAReservationAddedLaterMovesTheClientsAddress` — a MAC gets a dynamic lease, then a
  reservation is added for it pointing elsewhere; the next `Allocate` moves it. Asserts the
  vacated address is genuinely free (a second client can take it) and that `Leases()` no longer
  lists the old address for the moved MAC.
- `TestAReservationStealsAnAddressFromAnotherClientsLease` — one MAC holds a dynamic, unexpired
  lease; a reservation is added for a *different* MAC pointing at that same address; the
  reservation wins. Asserts the original holder is gone from `Leases()` (not just orphaned) and
  that a fresh `Allocate` for the dispossessed MAC is *not* treated as a renewal of the address
  it just lost.

Both passed on first run against the already-correct `commit` closure — this is expected; the
reviewer had already hand-traced the closure as correct, and the finding was about missing
*coverage*, not a bug. Kept both tests since they now pin behavior that had no test before.

### Commands run and output (post-fix)

```
$ go clean -testcache && go test ./internal/dhcpd/ -v
... (23 allocator/iface tests, all PASS)
PASS
ok  	github.com/yoshiofthewire/kydns-server/internal/dhcpd	0.003s

$ go test ./internal/dhcpd/ -race -count=2
ok  	github.com/yoshiofthewire/kydns-server/internal/dhcpd	1.012s

$ go vet ./internal/dhcpd/
(no output)

$ gofmt -l internal/dhcpd/
(no output)
```

18 allocator tests total (14 original + 4 new), plus Task 4's 9 iface tests, all pass under
`-race -count=2`.

## What changed

Added `internal/dhcpd/alloc.go` and `internal/dhcpd/alloc_test.go`, taken verbatim from the
brief with one deliberate deviation: **`Allocator.Reconfigure` was not implemented**, per the
correction in the task instructions. The brief's Step 3 code block included it; I dropped the
method and its doc comment entirely rather than commenting it out or stubbing it. Nothing else
in this part or its test suite references `Reconfigure`, so removing it did not require touching
any other method — `Allocate`, `free`, and `usable` all read `a.cfg` directly and don't care how
it got there.

Everything else — `Lease`, `Config`, `NewAllocator`, `Load`, `SetReservations`, `Allocate`,
`Release`, `Decline`, `Quarantine`, `Leases`, `NameTaken`, and the unexported `free`/`usable`/
`inRange`/`u32` helpers — is exactly as specified in the brief.

## Process followed

1. Wrote `alloc_test.go` verbatim from the brief's Step 1 code block.
2. Ran the targeted test subset; confirmed it failed to compile with `undefined: Config`,
   `undefined: Allocator`, `undefined: NewAllocator`, `undefined: quarantineFor`,
   `undefined: Lease` — the expected failure (the brief predicted `undefined: NewAllocator`
   specifically; the others are the same root cause, just more of the missing symbols were
   surfaced by the compiler in one pass).
3. Wrote `alloc.go` verbatim from the brief's Step 3 code block, omitting `Reconfigure`.
4. Ran the full package test suite — all tests pass, including Task 4's `iface_test.go` tests
   which were untouched.
5. Ran the race detector twice over the suite.
6. Ran `go vet` and `gofmt -l`.
7. Self-reviewed the diff: confirmed no `Reconfigure` reference remains anywhere in the file,
   confirmed the `commit` closure still does both deletes as the task's "watch for" note
   flagged, confirmed `NameTaken` only compares to other MACs and only unexpired leases.

## Commands run and output

```
$ go test ./internal/dhcpd/ -run 'TestAllocate|TestReservation|TestAReserved|TestQuarantined|TestDecline|TestExpired|TestExhaustion|TestLoad|TestNameTaken' -v
# github.com/yoshiofthewire/kydns-server/internal/dhcpd [...]
internal/dhcpd/alloc_test.go:11:19: undefined: Config
internal/dhcpd/alloc_test.go:12:9: undefined: Config
internal/dhcpd/alloc_test.go:22:39: undefined: Allocator
internal/dhcpd/alloc_test.go:25:9: undefined: NewAllocator
internal/dhcpd/alloc_test.go:127:7: undefined: NewAllocator
internal/dhcpd/alloc_test.go:148:17: undefined: quarantineFor
internal/dhcpd/alloc_test.go:194:11: undefined: Lease
FAIL	github.com/yoshiofthewire/kydns-server/internal/dhcpd [build failed]
FAIL
```
(confirmed the expected pre-implementation compile failure)

```
$ go test ./internal/dhcpd/ -v
--- PASS: TestAllocateTakesTheLowestFreeAddress (0.00s)
--- PASS: TestAllocateRenewsTheSameClient (0.00s)
--- PASS: TestAllocateHonoursARequestedAddress (0.00s)
--- PASS: TestAllocateIgnoresARequestedAddressThatIsTaken (0.00s)
--- PASS: TestAllocateIgnoresARequestedAddressOutsideTheRange (0.00s)
--- PASS: TestReservationWinsOverEverything (0.00s)
--- PASS: TestAReservedAddressIsNotHandedOutDynamically (0.00s)
--- PASS: TestAllocateSkipsTheHostAndGateway (0.00s)
--- PASS: TestQuarantinedAddressIsSkippedThenReleased (0.00s)
--- PASS: TestDeclineQuarantines (0.00s)
--- PASS: TestExpiredLeasesAreReusable (0.00s)
--- PASS: TestExhaustionRefuses (0.00s)
--- PASS: TestLoadRestoresLeasesAcrossARestart (0.00s)
--- PASS: TestNameTaken (0.00s)
--- PASS: TestIsVethReadsDevtype (+5 subtests) (0.00s)
--- PASS: TestParseDefaultGateway (0.00s)
--- PASS: TestParseDefaultGatewayWithNoDefaultRoute (0.00s)
--- PASS: TestSuggestRangeTakesTheUpperHalf (+2 subtests) (0.00s)
--- PASS: TestSuggestRangeRefusesATinySubnet (0.00s)
PASS
ok  	github.com/yoshiofthewire/kydns-server/internal/dhcpd	0.003s
```

```
$ go test ./internal/dhcpd/ -race -count=2
ok  	github.com/yoshiofthewire/kydns-server/internal/dhcpd	1.009s
```

```
$ go vet ./internal/dhcpd/
(no output)

$ gofmt -l internal/dhcpd/
(no output)
```

## Brief vs. instructions: what was ambiguous or wrong

- The only discrepancy was the one already flagged in the task instructions: the brief's Step 3
  code includes `Reconfigure`, which nothing in this part or its planned sequel calls. Dropped
  it per the explicit correction. No other part of the brief needed reinterpretation — the code
  block was complete and self-consistent, and the test file needed zero edits to pass once
  `alloc.go` existed.

## What was deliberately left alone

- `SetReservations`'s doc comment still says "Part 2 feeds this from services; until then it is
  only ever set to an empty map" — left as-is since it's accurate and this task doesn't touch
  the caller side.
- Did not touch `iface.go` or `iface_test.go` (Task 4); confirmed no naming collisions between
  the two test files (`epoch`, `testConfig`, `newTestAllocator` are all new names, not present
  in `iface_test.go`).
- No `Reconfigure`-shaped seam was substituted in its place (e.g. no stub, no TODO comment) —
  the correction says drop it entirely, so there's nothing marking its absence beyond this
  report.
