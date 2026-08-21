# Task 10: Runtime wiring — report

Branch `worktree-dhcp-part1`, from `a5982be`.

## What was implemented

The poller now always exists and always runs, its source swapped at runtime. A
`dhcpRunner` owns the built-in listener's lifecycle and is the only path that
binds or closes it; it is reconciled at boot and from `Apply`. The Discovered
page and the leases API now read a separate `DiscoveryOn` predicate rather than
inferring "enabled" from a non-nil lease provider.

### Files changed

| File | Change |
| --- | --- |
| `internal/app/dhcp.go` | New. `dhcpWanted`, `dhcpRunner` (`Reconcile`/`build`/`stopLocked`/`Status`), `dhcpConfigEqual`, `parseSetting`, `ForeignServerError`. |
| `internal/app/dhcp_test.go` | New. Role rule, config-equality coverage, replica refusal, failure reporting, `parseSetting`. |
| `internal/app/serve.go` | Poller always constructed; promotion/role block moved above `liveComponents`; runner constructed and reconciled; `leaseFn` simplified; `DiscoveryOn` wired to web and adminapi; `go poller.Run(ctx)` unconditional; dead restart-banner machinery removed. |
| `internal/app/apply.go` | `dhcp *dhcpRunner` field; `Apply` reconciles the runner and swaps the lease-file source; `SetInterval` kept under the existing nil guard. |
| `internal/app/apply_test.go` | Added `TestApplySwapsTheLeaseSource`. |
| `internal/app/settings_test.go` | Removed `TestRestartPending` (the function it tested is gone). |
| `internal/discovery/poller.go` | Added `Poller.Enabled()`. |
| `internal/web/middleware.go` | Added `Options.DiscoveryOn`; rewrote the doc comment so the on/off signal is named. |
| `internal/web/discovered.go` | Three call sites now consult `discoveryOn()`; added `leases()` helper. |
| `internal/web/discovered_test.go` | All five `srv.o.Leases` sites now set `DiscoveryOn`; added `TestDiscoveredOnOffFollowsDiscoveryOn`. |
| `internal/adminapi/api.go` | `WithProviders` takes `discoveryOn`; `promoteLease` consults it; added `leaseList()`. |
| `internal/adminapi/discovery_test.go` | Updated for the third argument. |
| `packaging/kydns.service` | Capability comment now covers port 67 and says why no raw sockets are needed. |

## TDD evidence

### RED

```
$ go test ./internal/app/ -run TestDHCPWanted -v
# github.com/yoshiofthewire/kydns-server/internal/app [github.com/yoshiofthewire/kydns-server/internal/app.test]
internal/app/dhcp_test.go:29:14: undefined: dhcpWanted
FAIL	github.com/yoshiofthewire/kydns-server/internal/app [build failed]
FAIL
```

### GREEN

```
$ go test ./internal/app/ -run 'TestDHCP|TestReconcile|TestParseSetting' -count=1 -v
--- PASS: TestDHCPWantedUnlessReplica (0.00s)
    --- PASS: .../enabled_on_a_primary
    --- PASS: .../enabled_on_a_standalone_node
    --- PASS: .../disabled
    --- PASS: .../enabled_with_no_interface
    --- PASS: .../enabled_on_a_replica
--- PASS: TestDHCPConfigEqualCoversEveryBuildInput (0.00s)   [8 subtests]
--- PASS: TestReconcileOnAReplicaNeverStarts (0.00s)
--- PASS: TestReconcileReportsWhyItCannotStart (0.00s)
--- PASS: TestParseSettingNamesTheField (0.00s)
ok  	github.com/yoshiofthewire/kydns-server/internal/app	0.005s
```

The R12 web change produced a genuine RED of its own before the tests were
updated — four pre-existing tests failed the moment `Enabled` stopped meaning
"Leases is non-nil":

```
--- FAIL: TestDiscoveredListsLeases
--- FAIL: TestShadowedLeaseIsMarked
--- FAIL: TestLeaseShadowedByManualRecord
--- FAIL: TestPromoteLeaseCreatesService
```

The new `TestDiscoveredOnOffFollowsDiscoveryOn` was mutation-checked: reverting
`discovered.go` to `s.o.Leases != nil` makes it fail with "with discovery off
the page still listed a lease", then the revert was undone. So the test proves
the mechanism rather than merely naming it.

## How each override was handled

**R1 — replica is the exception.** `dhcpWanted` ends `&& role != RoleReplica`.
The test is `TestDHCPWantedUnlessReplica` and carries a `RoleStandalone` case
expecting `true`, alongside the brief's four.

**R2 / R2a — accessor and construction order.** Used `roleHolder.Current`
directly as the `func() Role` (a method value; no wrapper closure needed). The
promotion block (`st.Promotion`, `RoleAtBoot`, its log line, `NewRoleHolder`)
moved above `live := &liveComponents{...}`; `errs := make(chan error, 3)` moved
down with it to stay next to its first use. Nothing between the old and new
positions depended on the block, and the full suite — including
`replication_e2e_test.go` and `promote_test.go` — passes.

**R6 — parse, do not panic.** `netip.MustParseAddr` replaced by
`parseSetting(key, value)`, which names the failing field
(`dhcp.range_start`, `dhcp.range_end`, `dhcp.gateway`) and returns an error
`build()` already propagates.

**R22 — a probe that could not run is not a clear.** A `DetectForeign` error
now refuses:

```
could not check whether another DHCP server is already answering on %q, so refusing to start: %w
```

Task 8's wrapped causes (`probe socket:`, `probe send:`, …) come through
verbatim. I also dropped the brief's ", or enable the override if you run two
deliberately" from `ForeignServerError`: Part 1 has no override key, and
pointing an operator at a setting that does not exist is its own bug. The
message now ends "Turn it off there first, then enable the built-in server
again".

**R12 — do not delete the guards.** `web.Options.DiscoveryOn func() bool` added
next to `Leases`, with the doc comment rewritten to say which field carries the
on/off signal. `discovered.go` consults `s.discoveryOn()` at all three sites.
`WithProviders` now takes a third argument and `promoteLease` uses it;
`listLeases` still returns an empty list. Both call sites and all six test
sites updated; no shim, no fallback.

The single source of truth is the poller's own source: I added
`Poller.Enabled()` (`p.source() != nil`) and wired `DiscoveryOn: poller.Enabled`
for both transports. That is true exactly when the built-in server is running
or a lease file is configured, because those are the only two things that ever
call `SetSource`, and it is evaluated per request.

**R27 — subnet containment.** `build()` refuses when `info.Subnet` does not
contain both `Start` and `End`, naming the range, the subnet and the interface.

**R28 — packaging.** No directives added; both were already present. Only the
comment changed, to cover port 67 and to record that no raw sockets are needed
because every reply is broadcast.

**Carried from Task 7.** `Reconcile` calls `d.stopLocked()` on every path that
reaches `build()`+`Start()`, so a second `Start` without an intervening `Stop`
is unreachable and the `cancel` field cannot be overwritten. There is a comment
at that call marking the ordering as load-bearing.

## Concurrency note — what I found

`Reconcile` holds `d.mu` and calls `d.role()`, which takes `RoleHolder`'s
`RWMutex`. Nothing calls `Reconcile` while holding the role lock:

- `RoleHolder.Current` and `RoleHolder.Set` (`internal/app/role.go:63,71`) each
  take and release the lock inside themselves; neither calls out while held.
- `replicaPromoter.Promote` (`internal/app/replication.go:243`) calls
  `p.role.Current()` and `p.role.Set(RolePrimary)` as separate statements and
  holds no lock across them.

So the lock order is `d.mu → RoleHolder.mu` everywhere, with no path in the
other direction. `go test ./internal/app/... ./internal/discovery/... -race`
passes.

**Gap worth naming:** nothing calls `Reconcile` on promotion. The role is read
per `Reconcile` as specified, so a promoted node will start DHCP at the next
settings save or restart — but not at the instant of promotion. Wiring that up
means giving `replicaPromoter` the runner and the settings holder; it is safe
to do (the promoter holds no lock when it would call), but it is outside the
files this task was scoped to, so I did not do it. Flagging rather than
guessing.

## A consequence I found in self-review, and fixed

Making the lease-file source swappable at runtime means `dhcp_lease_file` now
applies live — `Apply` calls `poller.SetSource(&dhcp.DnsmasqSource{...})`. But
`restartPending` (`serve.go`) still listed it as restart-required, so after this
change the Settings page would have told an operator to restart a server that
had already picked the file up. `dhcp_lease_file` was the last entry left
(`private_domain` had gone earlier), so the app-side machinery — `restartPending`,
`app.RestartItem`, `orOff`, and the `RestartPending` closure in `Serve` — was
dead as well as wrong, and is deleted. `web.Options.RestartPending` and
`web.RestartItem` stay: the web side is generic, nil-safe, and renders no banner
for a nil provider.

`TestRestartPending` went with the function. It is replaced by
`TestApplySwapsTheLeaseSource`, which proves the behaviour that made the banner
obsolete: setting `dhcp_lease_file` turns discovery on through `Apply`, and
clearing it turns discovery off, with no restart.

## Other self-review findings

- The zone holder's `if poller != nil` guard (`serve.go:100`) is **kept**, and
  now carries a comment saying why: the poller's `onChange` rebuilds that
  holder, so the holder is constructed first and its initial `Rebuild()` really
  does run while the variable is nil. Deleting this one would panic at startup.
- The `if l.poller != nil` guard in `Apply` is **kept** for the same class of
  reason: `liveComponents` is a struct tests build directly, and
  `TestApplyDoesNotPanicWithDiscoveryOff` sets `live.poller = nil` on purpose.
  The field comment changed from "nil when DHCP discovery is off" to "nil only
  in tests that do not build one", so it no longer claims to be an on/off flag.
- `Apply` swaps the lease-file source **only when `DHCPEnabled` is false**, and
  `stopLocked` returns early when nothing is running — so a runner that never
  started cannot clobber a configured lease-file source, and a running built-in
  server cannot be unhooked from DNS by the lease-file branch.
- `dhcpRunner.Status` has no production caller yet; the UI surface is Part 2.
  It is exercised by tests.
- No test opens a socket. The failure-path test uses a non-existent interface
  name, which `dhcpd.Qualifies` refuses at `net.InterfaceByName` before any
  socket work.

## Concerns

- **Boot is delayed when DHCP is enabled.** `dhcpRun.Reconcile(snap.Raw)` runs
  before the DNS and admin listeners start, and `build()` waits up to 2s (5s
  ceiling) in `DetectForeign`. That is the spec's start-time gate working as
  designed, but it is a visible startup cost on exactly the nodes that turn
  DHCP on, and it is worth knowing before someone reports "kydns is slow to
  start".
- **R22 has no escape hatch in Part 1.** A host where the probe cannot open
  `:68` — something else already bound to it, for instance — cannot enable the
  built-in server at all until the cause is cleared. That is the intended
  trade, recorded here so Part 2's override setting lands against a known case.

## Verification

```
$ go build ./...            # clean
$ go vet ./...              # clean
$ gofmt -l internal/        # no output
$ go test ./... -count=1    # 19 packages, all ok, 0 failures
$ go test ./internal/app/... ./internal/discovery/... -count=1 -race   # ok
```
