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
