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

## Fix round 1

Seven review findings, all in `internal/dhcpd/rogue.go` and `internal/dhcpd/rogue_test.go`. Nothing
else was touched; `go.mod`/`go.sum` are unchanged.

### What changed, per finding

- **F1 (Critical, R23) — the probe could not receive the reply.** `newProbeDiscovery` now builds
  `dhcpv4.NewDiscovery(mac, dhcpv4.WithBroadcast(true))` (`rogue.go:65-71`). With the flag clear and
  `ciaddr`/`giaddr` zero, RFC 2131 §4.1 has the server unicast the OFFER to `yiaddr`/`chaddr` — a MAC
  on no NIC here and an address we do not hold — so the answer was structurally unreceivable on
  exactly the networks this feature exists for.
- **F2 (R24) — untestable receive path.** Extracted `newProbeDiscovery(mac)` and
  `readReplies(conn net.PacketConn, xid dhcpv4.TransactionID) []reply` (`rogue.go:65-111`).
  `DetectForeign` is now socket + deadline + send + `collectForeign(readReplies(...), self)` and is
  the only untested part. The deadline arithmetic stays in `DetectForeign`; the read loop, the
  unparseable-packet skip, and the correlation filter moved to the tested side.
- **F3 (R25) — correlate by transaction ID.** The `strings.EqualFold` chaddr comparison is gone
  (with the `strings` import); `readReplies` keeps a reply iff `m.TransactionID == xid`. A server
  answering with `hlen = 0` — which `FromBytes` truncates `ClientHWAddr` to — no longer has its
  genuine OFFER dropped.
- **F4 — OFFER with no option 54.** `reply` pairs each parsed message with the datagram's source
  address; `collectForeign` falls back to that source when `ServerIdentifier()` does not parse
  (`rogue.go:136-139`). Our own server cannot be falsely reported through it: the source would be
  our own address, which the existing `id == self` check already excludes.
- **F5 — unlabeled errors.** `probe mac: %w`, `probe packet: %w`, `probe deadline: %w`, matching the
  existing `probe socket:`/`probe send:` style. Every path out of `DetectForeign` now names what
  failed, which is what Task 10 shows an operator when it refuses to start.
- **F6 — `String()` rendering "invalid IP".** Prints `unknown` when `!f.Offered.IsValid()`.
- **F7 — SO_REUSEADDR comment.** Narrowed to what is true: it lets the bind succeed where a host
  DHCP client on `:68` would otherwise refuse, and promises nothing about which socket a unicast
  datagram reaches. The sockopt itself is unchanged.

### Test double: why not `captureConn`

`captureConn` (`server_test.go:19`) embeds a nil `net.PacketConn` and overrides only `WriteTo`; it is
a write sink. `readReplies` calls `ReadFrom`, which on `captureConn` would dispatch to the nil
embedded interface and panic, and there is no way to feed it scripted input. `rogue_test.go` adds
`scriptConn`, the read-side mirror: it replays a fixed list of datagrams and then returns
`os.ErrDeadlineExceeded`, the way a passed deadline does. Same shape, same no-socket guarantee.

### RED

Method: the extraction (F2's `newProbeDiscovery`/`readReplies`/`reply`) was applied first with the
pre-fix *decisions* left in place — `NewDiscovery(mac)` with no broadcast, the chaddr filter, no
option-54 fallback, the old `String()`. The tests were then written against that, so each failure
below is a real assertion failure on the shipped behaviour, not an `undefined:` compile error. The
only difference between the RED and GREEN test files is that `readReplies` still took the probe MAC
as a parameter in the pre-fix version, so the four call sites read `readReplies(conn, probeChaddr,
xid)`; the assertions are byte-identical.

```
$ go test ./internal/dhcpd/ -run 'Foreign|ReadReplies|NewProbeDiscovery' -count=1
--- FAIL: TestCollectForeignFallsBackToTheSourceWithoutAServerID (0.00s)
    rogue_test.go:131: collectForeign = [], want one entry from the source address
--- FAIL: TestForeignStringWithoutAnOfferedAddress (0.00s)
    rogue_test.go:141: String() = "192.168.1.1 (offering invalid IP)", want "192.168.1.1 (offering unknown)"
--- FAIL: TestNewProbeDiscoveryAsksForABroadcastReply (0.00s)
    rogue_test.go:153: flags = 0x0000, want the broadcast bit set
--- FAIL: TestReadRepliesKeepsAnOfferWhoseChaddrDiffers (0.00s)
    rogue_test.go:165: readReplies = [], want the offer kept: its transaction ID is ours
--- FAIL: TestReadRepliesDropsAnotherClientsOffer (0.00s)
    rogue_test.go:178: readReplies = [{msg:0x3d59cb1669a0 src:...}], want none: that answers somebody else's DISCOVER
FAIL	github.com/yoshiofthewire/kydns-server/internal/dhcpd	0.003s
```

- F1 is `TestNewProbeDiscoveryAsksForABroadcastReply`: `flags = 0x0000` is the defect verbatim.
- F3 is the pair `TestReadRepliesKeepsAnOfferWhoseChaddrDiffers` (an OFFER with `hlen = 0`, right
  xid — pre-fix it was silently dropped, the false-clear direction) and
  `TestReadRepliesDropsAnotherClientsOffer` (matching chaddr, foreign xid — pre-fix it was kept).
- The four existing `collectForeign` tests passed in this run, i.e. the extraction did not change
  their behaviour.

### GREEN

```
$ go test ./internal/dhcpd/ -run 'Foreign|ReadReplies|NewProbeDiscovery' -count=1 -v
--- PASS: TestCollectForeignIgnoresOurOwnOffers (0.00s)
--- PASS: TestCollectForeignReportsAnotherServer (0.00s)
--- PASS: TestCollectForeignDedupesOneServerAnsweringTwice (0.00s)
--- PASS: TestCollectForeignIgnoresNonOffers (0.00s)
--- PASS: TestCollectForeignFallsBackToTheSourceWithoutAServerID (0.00s)
--- PASS: TestForeignStringWithoutAnOfferedAddress (0.00s)
--- PASS: TestNewProbeDiscoveryAsksForABroadcastReply (0.00s)
--- PASS: TestReadRepliesKeepsAnOfferWhoseChaddrDiffers (0.00s)
--- PASS: TestReadRepliesDropsAnotherClientsOffer (0.00s)
--- PASS: TestReadRepliesSkipsGarbageAndKeepsReading (0.00s)
--- PASS: TestReadRepliesEndsAtTheDeadline (0.00s)
PASS
ok  	github.com/yoshiofthewire/kydns-server/internal/dhcpd	0.003s
```

Seven new tests, four pre-existing ones unchanged in substance (they now pass through a `wire()`
helper that wraps messages as `reply` values with no source address, since all four carry option 54
and never consult it). New tests build addresses the shape the wire produces — 4-byte
`net.IP{192, 168, 1, 1}` and real `ToBytes`/`FromBytes` round-trips — rather than 16-byte
`net.ParseIP` values.

### Full verification

```
$ go build ./...                            → no output
$ go test ./internal/dhcpd/ -count=1        → ok (66 PASS: 59 pre-existing + 7 new)
$ go test ./internal/dhcpd/ -race -count=2  → ok 1.015s, no race
$ go test ./... -count=1                    → 19 packages, all ok, 0 FAIL
$ go vet ./...                              → no output
$ gofmt -l internal/dhcpd/                  → no output
$ go mod tidy; git diff go.mod go.sum       → no output (unchanged)
$ git status --short                        → only rogue.go and rogue_test.go modified
```

No test in `rogue_test.go` opens a socket: grepped clean for `net.Listen`, `net.Dial`,
`ListenPacket`, `ListenUDP`, `AF_PACKET`, `nclient4`.

### Concerns

None blocking. Two things on record:

- `DetectForeign` is still untested end-to-end (it opens a real socket), as designed. What remains
  untested there is now only the socket construction, the deadline arithmetic, and the send — Task 10
  is the first place those run for real.
- Deliberately out of scope and unchanged: the read loop still ends only on the absolute deadline,
  not on `ctx` cancellation. Bounded at 2 s; recorded as a deferred minor.
