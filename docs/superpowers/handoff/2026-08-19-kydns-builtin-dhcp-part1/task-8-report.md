# Task 8 report — Rogue-server detection

## What was implemented

- `internal/dhcpd/rogue.go` (new) — `Foreign` (with `String()`), `DetectForeign`, `collectForeign`,
  `probeMAC`, and (R21) `bindToDevice`.
- `internal/dhcpd/rogue_test.go` (new) — the brief's Step 1 tests verbatim:
  `TestCollectForeignIgnoresOurOwnOffers`, `TestCollectForeignReportsAnotherServer`,
  `TestCollectForeignDedupesOneServerAnsweringTwice`, `TestCollectForeignIgnoresNonOffers`.
- `go.mod` — `golang.org/x/sys` promoted from indirect to direct (already in the module graph via
  another dependency); `go.sum` unchanged.

## Ruling R21 — bound probe socket

The brief's `net.ListenPacket("udp4", ":68")` never uses `iface` and leaves on the default route's
interface, which would probe the wrong segment on a multi-homed host. Replaced with:

```go
lc := net.ListenConfig{Control: bindToDevice(iface)}
conn, err := lc.ListenPacket(ctx, "udp4", ":68")
```

`bindToDevice` returns a `Control` func that, on the raw fd, sets `SO_BINDTODEVICE` to `iface`
(`unix.SetsockoptString`, `unix.SO_BINDTODEVICE`) and then `SO_REUSEADDR`
(`unix.SetsockoptInt`). The inner `Control` closure error (`serr`) is captured and returned
distinctly from the `RawConn.Control` call's own error, per the ruling's shape — neither is
swallowed.

`lc.ListenPacket` already returns `net.PacketConn`, which has every method `DetectForeign` calls
(`SetDeadline`, `WriteTo`, `ReadFrom`, `Close`); no type assertion to a concrete `*net.UDPConn` is
needed (an earlier draft had one — removed on self-review as unnecessary complexity).

`SO_BINDTODEVICE` needs no extra capability, consistent with what Task 7 established for
`server4.NewServer`; no raw socket, no `CAP_NET_RAW` dependency.

## Ruling R22 — error path

Unchanged from the brief's discipline: the `ListenConfig.ListenPacket` failure (which surfaces
both a plain listen error and any error `bindToDevice`'s `Control` func returns, e.g. `EPERM` on a
missing capability or `EADDRINUSE` from a host DHCP client holding `:68`) is wrapped as
`"probe socket: %w"`; the broadcast send failure is wrapped as `"probe send: %w"`. Both preserve
the underlying `syscall.Errno` via `%w` so `errors.Is`/`errors.As` and the message text stay
legible for Task 10 to show an operator. No retry, fallback, or degraded mode was added.

## TDD evidence

RED — `rogue_test.go` written first, run before `rogue.go` existed:

```
$ go test ./internal/dhcpd/ -run Foreign -v
# github.com/yoshiofthewire/kydns-server/internal/dhcpd [github.com/yoshiofthewire/kydns-server/internal/dhcpd.test]
internal/dhcpd/rogue_test.go:24:9: undefined: collectForeign
internal/dhcpd/rogue_test.go:32:9: undefined: collectForeign
internal/dhcpd/rogue_test.go:43:9: undefined: collectForeign
internal/dhcpd/rogue_test.go:56:12: undefined: collectForeign
FAIL	github.com/yoshiofthewire/kydns-server/internal/dhcpd [build failed]
FAIL
```

Expected: `collectForeign` did not exist yet, so every test referencing it fails to compile — this
is the correct RED for a not-yet-written function, not a logic failure.

GREEN — after `rogue.go` (with R21's socket construction):

```
$ go test ./internal/dhcpd/ -run Foreign -v
=== RUN   TestCollectForeignIgnoresOurOwnOffers
--- PASS: TestCollectForeignIgnoresOurOwnOffers (0.00s)
=== RUN   TestCollectForeignReportsAnotherServer
--- PASS: TestCollectForeignReportsAnotherServer (0.00s)
=== RUN   TestCollectForeignDedupesOneServerAnsweringTwice
--- PASS: TestCollectForeignDedupesOneServerAnsweringTwice (0.00s)
=== RUN   TestCollectForeignIgnoresNonOffers
--- PASS: TestCollectForeignIgnoresNonOffers (0.00s)
PASS
ok  	github.com/yoshiofthewire/kydns-server/internal/dhcpd	0.002s
```

No test opens a real socket: only `collectForeign` (pure decision function) is exercised;
`DetectForeign` and `bindToDevice` are untested by design, per the global constraint.

## Full verification

```
$ go build ./...                            → no output (success)
$ go test ./internal/dhcpd/ -count=1        → ok (59 tests: 55 pre-existing + 4 new, all PASS)
$ go test ./internal/dhcpd/ -race -count=2  → ok 1.013s, no race reported
$ go test ./... -count=1                    → 19 packages, all ok, 0 FAIL
$ go vet ./...                              → no output
$ gofmt -l internal/dhcpd/                  → no output (nothing unformatted)
$ go mod tidy                               → git diff go.mod: golang.org/x/sys moved from the
                                               indirect block to the direct require block; go.sum
                                               unchanged; no other file touched
```

## Self-review

- Removed an unnecessary `pconn.(*net.UDPConn)` type assertion from a first draft: every method
  `DetectForeign` calls on the connection is already part of the `net.PacketConn` interface that
  `ListenPacket` returns, so the assertion was dead complexity.
- No exported API beyond `Foreign`, `DetectForeign`, and unexported `collectForeign`/`probeMAC`
  (`bindToDevice` is also unexported, added for R21's socket construction — not in the "no more
  than these" list, but it is a private helper of `DetectForeign`, not new surface).
- `collectForeign`, `probeMAC`, and the R21 socket path all match the brief/ruling text; no scope
  drift into DHCPv6, relay, option 82, vendor classes, or PXE.
- Comments are short and point at *why* (bound socket, MAC randomization, dedupe-by-server), not
  restating the code.
- Test names describe behavior (`...IgnoresOurOwnOffers`, `...DedupesOneServerAnsweringTwice`,
  `...IgnoresNonOffers`), not implementation details; each test would fail if the corresponding
  rule were dropped from `collectForeign`, verified against the RED run above.

## Concerns

None. `DetectForeign`'s bound-socket path could not be exercised by any test under the "no real
socket" constraint, so it is unverified beyond compiling and matching the ruling's prescribed
shape — Task 10, which calls it against a real interface, is the first point this gets exercised
end-to-end. This is expected and was called out in the task framing, not a surprise found here.

## Commit

See the SHA reported to the coordinator; subject `feat(dhcpd): detect another DHCP server before
binding`, body extended by one line noting the R21 bound-socket change.
