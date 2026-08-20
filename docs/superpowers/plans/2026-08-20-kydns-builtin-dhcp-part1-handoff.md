# Built-in DHCP Part 1 — handoff

Date: 2026-08-20
Branch: `worktree-dhcp-part1` (worktree at `.claude/worktrees/dhcp-part1`, based on `7dc7027`)
Plan: `docs/superpowers/plans/2026-08-19-kydns-builtin-dhcp-part1.md`
Spec: `docs/superpowers/specs/2026-08-19-kydns-builtin-dhcp-design.md` — the binding authority

## State

**6 of 11 tasks complete and reviewed clean. Task 7 is code-complete with an unverified fix round.**
Whole suite green at the time of writing: 19 packages, 0 failures, `go vet` clean.

| Task | Commits | State |
|---|---|---|
| 1 — poller `SetSource` | `bb0e951`, `f772632` | complete, review clean |
| 2 — settings columns + lease table | `ac86d78` | complete, review clean |
| 3 — lease persistence | `ce6fd7c` | complete, review clean |
| 4 — interface inspection | `606f8b1` | complete, review clean |
| 5 — allocator | `8891492`, `4fd5e19` | complete, review clean |
| 6 — conflict probe | `093575b` | complete, review clean |
| 7 — packet handling | `e59d9bb`, `0c091d7` | **fix landed, scoped re-review NOT run** |
| 8 — rogue detection | — | not started |
| 9 — settings validation | — | not started |
| 10 — runtime wiring | — | not started |
| 11 — API and CLI | — | not started |

### The one thing that is claimed but not established

Task 7's fix commit `0c091d7` claims to close a Critical defect: `Server.allocate`'s `commit` flag
gated only the conflict probe and never reached the allocator, so a bare DISCOVER — never followed by
a REQUEST — committed a full 24-hour lease *and* published the client's self-chosen option-12 hostname
into DNS. A reviewer demonstrated both with a scratch test before the fix. The implementer reports
40/40 tests passing afterwards.

**Nobody has verified the fix does what it says.** Resume by running the scoped re-review of
`e59d9bb..0c091d7` against the four findings in R15–R17 below before treating task 7 as done.

## How to resume

Work is driven by `superpowers:subagent-driven-development`: one implementer subagent per task, a
spec-and-quality review after each, a fix loop capped at five rounds, then a whole-branch review.

The live ledger is at `.superpowers/sdd/2026-08-19-kydns-builtin-dhcp-part1/progress.md`. **That
directory is git-ignored**, so it does not survive a clone or a `git clean -fdx` — which is why every
ruling is reproduced in this document. Task briefs and review packages for all 11 tasks are already
extracted there.

Next actions, in order:

1. Scoped re-review of `e59d9bb..0c091d7` against R15–R17.
2. Tasks 8 → 11, carrying the rulings below into each dispatch.
3. Whole-branch review, then `superpowers:finishing-a-development-branch`.

## Rulings

Decisions taken without the operator present. Each is reversible; each says what it costs if wrong.

**R1 — DHCP runs unless the node is a replica.** Task 10's `dhcpWanted` gates on
`role != RoleReplica`, not `role == RolePrimary`. `internal/app/role.go:15-19` has three roles, and
`RoleStandalone` is the normal single-node deployment; requiring primary would mean DHCP never ran for
most users. `serve.go:237` already uses the `!= RoleReplica` idiom. The spec's "a replica never serves
DHCP" is satisfied exactly. *Cost if wrong: a standalone node serves DHCP where someone expected only
primaries to — same single machine, no conflict risk.*

**R2 / R2a — role accessor and construction order.** The role is read via `roleHolder.Current()`;
`.Role()` does not exist. R2's placement was impossible as written: `live := &liveComponents{...}` is
built at `serve.go:195` but `roleHolder` only exists at `:213`. R2a moves the promotion/role block
(`st.Promotion()`, `RoleAtBoot`, its log line, `NewRoleHolder`) above the `liveComponents` literal — it
depends only on `st`, `cfg`, `logger`, and nothing between those lines depends on it. *Cost if wrong:
a compile error, caught in the same task.*

**R3 — `reflect.DeepEqual`, not `==`.** Task 2's round-trip test cannot compare `store.Settings` with
`==`; it contains `[]string`. Verified: `vet: struct containing []string cannot be compared`. *Cost if
wrong: none, mechanical.*

**R4 — pool size cap replaces the same-/24 rule.** Task 9 drops "range start and end must share a /24"
and caps the pool at 65536 addresses, keeping `end >= start`. `SuggestRange` takes the upper half of
any subnet down to /29, so on a /22 it proposes `x.y.2.0`–`x.y.3.254`, spanning two /24s — the wizard
would have suggested exactly what the validator rejects. A size cap is subnet-agnostic, so validation
still checks only the stored value and never host state. *Cost if wrong: an operator on /22 or wider
can configure a very large pool; the lease table is bounded by range size and 65536 is the guard.*

**R5 — no `Allocator.Reconfigure`.** Nothing calls it; a settings change rebuilds the server rather
than mutating a live allocator. *Cost if wrong: a later change re-adds it in a few lines.*

**R6 — `netip.ParseAddr`, not `MustParseAddr`.** Task 10 builds from whatever is in the settings row.
A row written before the validator existed, or edited directly in SQLite, would panic the whole server
at start rather than reporting a bad setting. *Cost if wrong: none, strictly safer.*

**R7 — fix the plan-mandated concurrency test gap.** The plan supplied three `SetSource` tests and none
was concurrent, but Task 10 calls `SetSource` from the settings-apply goroutine while `Run` polls in
its own — the entire purpose of task 1. `TestPollerSetInterval` already establishes the pattern. *Cost
if wrong: one test duplicating coverage the race detector would have caught anyway.*

**R8 — accept the implementer's `ApplySnapshot` change (out of brief).** The constraint "DHCP settings
never replicate" is not delivered by the `cv_settings_u` trigger alone. `ApplySnapshot` rewrites the
whole settings row from a pulled snapshot and already carried explicit preservation for
`dhcp_lease_file`, `discovery_interval`, `log_queries`, `log_client_ip`. Without the `dhcp_*` columns
in that list, a replica pulling *any* replicated settings change would silently overwrite its own local
DHCP configuration. This was a defect in the plan, not scope creep. *Cost if wrong: seven extra fields
preserved across snapshot application — the conservative direction.*

**R9 — `SuggestRange(subnet)` only.** The plan passed `host` and `gw`, used neither, then suggested
`_ = host` to placate a linter — doubly wrong, since Go does not warn on unused parameters and two dead
parameters are a YAGNI defect. The allocator already excludes host and gateway. *Cost if wrong: one
signature and one call site to widen later.*

**R10 — accept the implementer's fixture correction.** The plan's `TestParseDefaultGateway` used hex
`0100A8C0` claiming 192.168.1.1; it decodes to 192.168.0.1. Independently verified. They fixed the
input and kept the intended expectation rather than weakening the assertion. *Cost if wrong: none,
arithmetic.*

**R11 — enforce protected addresses on the reservation path.** `Allocate` case 1 never consulted
`usable()`, so a reservation naming the server's own address or the gateway would be handed to a
client. Fixed here rather than deferred to Part 2 because the allocator is the only component that
knows those two addresses — Part 2's resolver is given only the subnet. A `protected(ip)` predicate,
range-independent (reservations outside the range remain legal), gates case 1 and falls through to
normal allocation. *Cost if wrong: a deliberate reservation onto the gateway address stops working,
which is not a configuration anyone can want.*

**R12 — Task 10 must not simply delete the `poller == nil` guards.** They are not asking whether the
poller object exists; they stand in for "is a lease source configured", and the UI depends on the
distinction (`serve.go:244-249`, `:313-318`; `internal/web/discovered.go:21` and `:64` read
`s.o.Leases == nil` as the off signal). Making the poller always non-nil would leave the Discovered
page reporting discovery as enabled forever, and that flag is computed once at construction so it
cannot represent a source toggled at runtime. Task 10 adds `DiscoveryOn func() bool` to `web.Options`
and the adminapi equivalent, sets it to a live predicate, and rewrites the three call sites. *Cost if
wrong: one option field threaded through two packages; the alternative is a UI that lies.*

**R13 — Task 11's API surface.** Routes in this codebase are `/api/v1/...`, not `/api/...`. A lease
listing already exists: `GET /api/v1/leases` → `listLeases` (`api.go:222`, `:800`), returning
`{"leases":[{hostname,address,mac,expires}]}` with `expires` as a Unix int, and already returning an
empty list when no provider is wired. Built-in DHCP leases reach it through the same poller, so no
parallel DHCP-only endpoint is added. Task 11 adds only `GET /api/v1/dhcp/status` for what the existing
endpoint cannot express — running, and why not. *Cost if wrong: the DHCP tab reads two endpoints, which
it was going to do anyway.*

**R14 — drop the ICMP echo from the conflict probe.** The plan called `net.DialTimeout("ip4:icmp", …)`,
which needs `CAP_NET_RAW`; the service is granted `CAP_NET_BIND_SERVICE` and nothing else, precisely so
no raw sockets are needed. That branch would fail on every call and silently degrade to a passive cache
read — and the ARP cache only holds addresses the host has recently talked to, which is not the set we
are about to hand out. Replaced with an unprivileged active probe: one throwaway UDP datagram to force
the kernel to ARP, then read `/proc/net/arp` and treat a COMPLETE entry (flag `0x2`) as in-use. *Cost
if wrong: weaker than an ICMP sweep where the poke port is firewalled; DHCPDECLINE is the backstop and
a false negative costs one declined address.*

**R15 — an OFFER is a tentative hold, not a lease.** `Server.allocate`'s `commit` flag gated only the
probe and never reached `Allocator.Allocate`, whose commit closure unconditionally wrote a full lease
term. A DISCOVER never followed by a REQUEST therefore burned a pool address for hours and published an
attacker-chosen hostname into DNS. The fix gives the allocator an explicit per-call lease duration; the
OFFER path uses a 60-second hold **and an empty hostname**, the ACK path uses `cfg.LeaseTime` and the
real name. *Cost if wrong: two clients could briefly be offered the same address across a >60s
DISCOVER→REQUEST gap; DHCP tolerates that by design and the ACK path re-checks.*

**R16 — `Start` owns its own cancellable context.** Both goroutines in `Start` assumed the caller would
cancel, but Task 10 passes `context.Background()`. So the `<-ctx.Done()` watcher never exited (one
leaked goroutine per DHCP reconfigure) and the `ctx.Err() == nil` guard never fired, making every
deliberate stop log `Error("dhcp server stopped")` indistinguishable from a crash. `Start` now derives
its own context and `Stop` cancels it before `Close()`. *Cost if wrong: none — fewer goroutines, quieter
logs.*

**R17 — `normalizeMAC` parses rather than lowercases.** It was safe only because its sole input was
`m.ClientHWAddr.String()`. Part 2 compares operator-typed reservations against it, where dashes,
missing zero-padding, or no separators would silently fail to match. Both normalizers now go through
`net.ParseMAC`, closing a hazard Part 2's own self-review had flagged as guarded by nothing but a
comment. *Cost if wrong: none.*

## Part 2's plan is now stale

`docs/superpowers/plans/2026-08-19-kydns-builtin-dhcp-part2.md` was committed before these rulings and
must be revised before it is executed, or its implementers will write code against signatures that no
longer exist:

1. R9 — Task 4's `dhcpSuggest` calls `SuggestRange(info.Subnet, info.Addr, info.Gateway)`; the signature
   is now `SuggestRange(subnet)`.
2. R15 — verify nothing assumes the old `Allocate(mac, hostname, requested)` signature. Part 2 only
   calls `SetReservations` today, so this is a read-through check rather than a known break.
3. R13 — `/api/dhcp/status` and `/api/dhcp/suggest` become `/api/v1/dhcp/...`; the `writeError` helper
   does not exist, the real one is `writeErr(w, status, code, field, msg)`.
4. R13 — the test helper `newTestAPI` does not exist; it is `newAPI(t)` / `newAPIWithProviders(t)`.
5. R12 — the web tab reads discovery state from `DiscoveryOn func() bool`, not `Leases != nil`.
6. R17 — the self-review paragraph describing the two normalizers as "guarded only by a comment" is no
   longer true and should be rewritten.

## Deferred minor findings

Carried for the whole-branch review to triage; none blocks.

- Task 2: the comment above `dhcp_leases` (`store.go:145`) refers forward to tables ~80 lines below.
- Task 2: `dhcp_leases` sits before the `cv_` block in the base schema and after the ALTERs in the
  migration — harmless ordering difference.
- Task 4: `Qualifies` checks veth before the IPv4 check, differing from the constraint prose. Arguably
  the more actionable order.
- Task 4: `Inspect` takes the first IPv4 in OS-reported order; "first" has no semantic meaning on a
  multi-address interface.
- Task 6: the probe budget is ~100.5 ms rather than 100 ms — the `/proc/net/arp` read happens after the
  deadline is spent. Bounded (pseudo-file), but structural, on every call.
- Task 6: no test exercises `parseARPTable`'s short/malformed-line guard; correct by inspection only.
- Task 6: `c.Write` return values discarded implicitly rather than `_, _ =`.
- Task 7: the `allocate()` comment says renewals are not probed, but the gate is `!commit` — i.e. the
  OFFER path always probes. Comment, not behaviour.

## Process notes worth keeping

- **The pre-flight scan paid for itself.** It found four defects in the plan before any code was
  written, the worst being R1 — DHCP would never have run on a standalone node, which is most
  deployments.
- **Two defects were found by implementers, not by me or the reviewers** (R8, R10). Both were reported
  as concerns rather than silently worked around, which is the behaviour to keep asking for.
- **A brief-extraction loop failed silently** because the worktree sandbox rejected it, and task 7 ran
  without its brief file. The implementer noticed, fell back to the identical plan section, and said
  so. Check the output of batch commands.
- **Material corrections belong in the ledger, not only in the dispatch prompt.** A reviewer correctly
  flagged that it could not corroborate an instruction I had given task 6, because that instruction
  lived only in the dispatch.

## Unrelated repair made along the way

`7dc7027` (already on `main`) completes the AGPLv3 → MIT relicense that `2f4a233` started and left
half-done. That commit had replaced the licence file but not the `nfpm.yaml` declaration, the
`Makefile` tarball step, `verify-package.sh`, the README link, or the web UI's footer and served
licence text — so the package and tarball builds referenced a deleted file and every operator was told
the software was AGPLv3. `TestNavFooterOpensLicense` had been red on `main` since.
