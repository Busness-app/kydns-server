# SDD ledger — plan: docs/superpowers/plans/2026-08-19-kydns-builtin-dhcp-part2.md

Spec: docs/superpowers/specs/2026-08-19-kydns-builtin-dhcp-design.md (read; binding authority)
Worktree: .worktrees/dhcp-part2, branch worktree-dhcp-part2, base e0662c9
Baseline: 19 packages ok, 0 failures, vet clean
Part 1's ledger (37 rulings) is at docs/superpowers/handoff/2026-08-19-kydns-builtin-dhcp-part1/progress.md
and its rulings still bind. This plan's amendments header block records the ones that changed it.

## Pre-flight scan

### Pairwise (tasks sharing a file or interface)

| A → B | A produces | B consumes | Found |
|---|---|---|---|
| T1 → T4 | `Settings.DHCPAllowForeign` | CLI override key | **DEFECT — no task owns the adminapi DTO field. See P1** |
| T1 → T4 | `dhcpRunner.Foreign()` | `/api/v1/dhcp/status` payload | **CONFLICT — the endpoint already exists. See P2** |
| T1 → T5 | the override + banner | DHCP tab | OK once P1/P2 land |
| T2 → T3 | `store.Service.MAC` | `Reservations(svcs, subnet)` | OK — field is genuinely absent today (model.go:140's MAC is `DHCPLease.MAC`) |
| T2 → T4 | `registry.ValidateMAC`, uniqueness | `"mac"` on the service DTO | OK |
| T3 → T1/app | `Reservations()` | must reach `Allocator.SetReservations` | **GAP — no task names the seam. See P5** |
| T3 → T4 | `[]ReservationProblem` | `"problems"` in status JSON | OK once P2 widens the provider |
| T4 → T5 | status + suggest endpoints | the tab | OK |
| T5 → Part 1 | `POST /dhcp/reserve` | promote-to-service | **OVERLAP — Part 1 already has this flow. See P6** |
| T6 → all | docs | — | OK |

### Self-consistency (per task)

| Task | Found |
|---|---|
| T1 | OK, given P1/P2. `foreignVerdict` now takes the probe error (decided this session). |
| T2 | **DEFECT — stale line refs. See P3.** `registry.validateService:63-98` and `registry.Invalid(field, code, ...)` are both correct. |
| T3 | OK |
| T4 | See P2. Route prefix, `writeErr`, `newAPI(t)` already corrected in the plan. |
| T5 | **DEFECT — routes need the session/CSRF wrappers. See P7** |
| T6 | OK |

### Global constraints vs the plan's own text

| Constraint | Found |
|---|---|
| "Use Part 1's `dhcpd.normalizeMAC`; do not write a second normalizer" | **CONTRADICTION — see P4.** It is unexported, and T2 defines `registry.NormalizeMAC`. The plan's own closing scope note says so. |
| "Reservations replicate" | OK — `cv_services_*` triggers already cover the services table; `services.mac` inherits that. |
| "Tests must not open a real DHCP socket" | OK |

## Rulings

Ruling: P1 — Task 1 owns the `dhcp_allow_foreign` field on the adminapi settings DTO, not just the
store column. No task's Files list names `internal/adminapi/settings.go` for it: Task 1 stops at the
store and validator, and Task 4 lists `internal/cli/settings.go` but not the DTO. So the CLI key would
have had nothing to write to and the web tab no way to set it. Part 1's R32 also applies — the field
needs BOTH `json:"dhcp_allow_foreign"` and `yaml:"dhcp_allow_foreign"` tags and must be wired through
`toSettingsDTO` and `fromSettingsDTO`, or a settings import silently blanks it. Cost if wrong: one
field added to a task that already touches the settings path.

Ruling: P2 — Task 4 WIDENS `GET /api/v1/dhcp/status`; it does not create it. Part 1 shipped that route
(`internal/adminapi/dhcp.go`) returning `{"running","error"}`, fed by
`WithDHCP(status func() (bool, error))`. A plain func cannot carry `supported`, `reason`, `foreign`,
`problems` or `dual_stack`. Decision: the provider becomes a small interface on the runner —
`WithDHCP(d interface{ Status() (bool, error); Foreign() []dhcpd.Foreign; Problems() []dhcpd.ReservationProblem; ... })`
— and Task 4 extends the existing handler and its existing tests rather than adding a second one.
Task 1 must not widen it early; it only adds `Foreign()` to the runner. Cost if wrong: one interface
to reshape in the task that already owns the endpoint.

Ruling: P3 — Task 2's line references are stale and are replaced by these, verified at e0662c9:
`store.Service` is `internal/store/model.go:19-33` (correct); the services schema is `store.go:36-43`
(correct); but `putService` does not exist — the writer is exported `Store.PutService` at
`store.go:502` with its INSERT at `:521`; the single-service SELECT is at `:574` and `Services()` at
`:628`. The plan's `:487-500` is view deletion and `:543` is unrelated. An implementer following them
would edit the wrong code. Cost if wrong: none, mechanical.

Ruling: P4 — the global constraint "use Part 1's `dhcpd.normalizeMAC`; do not write a second
normalizer" is not achievable and is restated rather than obeyed. `dhcpd.normalizeMAC` is unexported,
and exporting it would make `registry` import `dhcpd` (or the reverse) for one string function — a
dependency this codebase does not want, as the plan's own closing scope note argues. The real
requirement is behavioural: `registry.NormalizeMAC` and `dhcpd.normalizeMAC` must produce identical
output for any MAC a client can send. Part 1's R17 already made both parse via `net.ParseMAC` and
re-render, so dash, Cisco dot-quad and unpadded forms converge. Task 2 writes `registry.NormalizeMAC`
as a thin `net.ParseMAC` wrapper and its tests must include the same table Part 1's `TestNormalizeMAC`
uses, so the two are pinned to the same cases. Cost if wrong: two normalizers that agree by test
rather than by construction — which is what the code already does.

Ruling: P5 — Task 3 must wire `Reservations()` into the registry's existing change callback, and the
plan does not say so. `Reservations()` is pure, but nothing recomputes it when an operator adds a MAC
to a service, so the allocator would keep a stale map until the next DHCP reconfigure. The seam
exists: `registry.New(st, privateFQDN, onChange func() error)` at `internal/app/serve.go:116` already
fires on every registry write and today only rebuilds the zone holder. Task 3 extends that callback to
recompute reservations and call `Allocator.SetReservations`, and stores the resulting
`[]ReservationProblem` on the runner for P2's status payload. Cost if wrong: a reservation that only
takes effect after a settings change or a restart — which is exactly the "requires a restart" friction
Part 1 spent Task 1 removing.

Ruling: P6 — Task 5's `POST /dhcp/reserve` reuses the existing promote-to-service flow rather than
adding a parallel one. The spec is explicit: "The lease table's `Reserve` button promotes a lease to a
service with its MAC and address filled in, reusing the existing promote-to-service flow." Part 1
already ships that flow twice over — `internal/web/discovered.go` `postPromote` and
`POST /api/v1/leases/{ip}/promote`. The one thing genuinely new is filling the MAC in, which the
existing flow drops. Decision: Task 5 extends the existing promote path to carry the MAC, and
`/dhcp/reserve` is a thin caller of it, not a second implementation. Cost if wrong: one handler to
merge later instead of two to keep in step.

Ruling: P7 — Task 5's four routes take the same wrappers every other web route uses:
`s.requireSession(...)` for the GET and `s.requireCSRF(...)` for the three POSTs
(`internal/web/pages.go:35-43` is the pattern). The plan lists the routes bare. An unwrapped POST on
this page would let any origin change DHCP settings or plant a reservation. Cost if wrong: none — it
matches every neighbouring route.

Ruling: P8 — an extra task is inserted between Task 2 and Task 3, and it is not in the plan. Part 1's
whole-branch review found two allocator holes that are unreachable today only because
`SetReservations` is always handed an empty map, and Task 3 is the task that first hands it a
non-empty one:
  (a) allocation rule 1 commits a reservation with no freeness check, so a bare DISCOVER from a
      reserved MAC evicts whatever OTHER MAC currently holds that IP. The tentative-hold guard keys on
      the same MAC, so it does not cover this.
  (b) the tentative-hold guard requires `prev.IP == ip`, so it does not fire when a hold lands on a
      DIFFERENT address than the one held — which is exactly what adding a reservation for an address
      the client is not currently holding does.
Both are the same class as the Critical that took four fix rounds in Part 1: a bare DISCOVER damaging
a lease someone holds. They get their own task with their own tests rather than a bullet inside
Task 3, because that is what Part 1 learned the hard way. Order: T1, T2, **T2b**, T3, T4, T5, T6.
Cost if wrong: one extra review cycle on a task that is two guards and two tests.

## Progress
Task 1: implemented (commit 45b847f) — dhcp_allow_foreign end to end, foreignVerdict taking the probe
  error, the 15-minute watch, Server.ProbeForeign with an unexported ignoreXID.
Task 1: review — SPEC ✅. QUALITY approved, 0 Critical, 1 Important, 3 Minor.
  The reviewer verified the hard part two ways: removing `ignoreXID` makes the co-resident test fail
  with OUR OWN offer winning collectForeign's dedupe-by-ServerID and hiding the real server — Part 1's
  exact defect reproduced — and reintroducing a self-by-address filter makes it fail with an empty
  probe. So the test genuinely exercises our listener answering, and an address filter cannot creep
  back undetected. It also dropped the yaml tag itself and watched the round-trip test fail, confirming
  P1's guard is real. Goroutine lifecycle checked: no per-reconfigure leak, the Part 1 bug did not
  recur.
  Important: `internal/store/store.go:324`'s migration has zero coverage, and the report claimed
  otherwise. `Open` runs `schema` before `migrate`, and `TestOpenMigratesAnOlderDatabase`'s fixture has
  no settings table at all, so `CREATE TABLE IF NOT EXISTS` builds the current shape and the ALTER is a
  swallowed no-op. The reviewer deleted the whole migration line and the store suite stayed green. The
  migration itself is correct — they hand-built a Part 1 database and it fails without it — but the
  real upgrade path is exercised by nothing, and migration 4's dhcp_* ALTERs are equally uncovered.
Task 1: fix round 1/5 (3 addressed, 0 open; commits 45b847f..e3737da). Re-reviewer confirmed the new
  migration test is honest — user_version=3 with a hand-built pre-DHCP settings table forces migrate's
  loop to run indices 3 and 4 rather than leaning on CREATE TABLE IF NOT EXISTS — and that it asserts
  on the `Settings()` read, which is what actually fails, not on Open returning nil. Both mutants
  caught by the new test alone while the two pre-existing migration tests stayed green, which is what
  proves the hole was real. Also confirmed `dhcpConfigEqual` never compares DHCPAllowForeign, so
  syncing d.current for the once-only log cannot suppress a later real config change.
Task 1: minor (deferred): `ProbeForeign`'s own body is uncovered — tests drive `detectForeign`
  directly, so the `probeConn(ctx, s.opts.Iface.Name)` + `s.ignoreXID` pairing never executes. Two
  arguments, same class as the Reconcile wiring gap.
Task 1: complete (commits e0662c9..e3737da, review clean)

Ruling: P3a — amends P3, which was incomplete. The implementer was right: there IS an unexported
`putService(tx *sql.Tx, svc Service)` holding the INSERT/UPDATE, and exported `Store.PutService` just
wraps it. Verified at HEAD. My P3 said "there is no putService", which was wrong — I had grepped for
`func (s *Store) putService` (a method) and it is a plain function. The practical consequence is in
their favour: editing `putService` covers the import/snapshot path too, which editing only the
exported wrapper would have missed. Recording because a ruling stated as verified fact and then found
wrong is exactly the thing that must not stay in the ledger uncorrected.

Task 2: implemented (commit 23cc48c) — Service.MAC, registry.NormalizeMAC/ValidateMAC, uniqueness in
  PutService and ReplaceAll, services.mac column and migration.
Task 2: review — SPEC ✅. QUALITY approved, 0 Critical, 2 Important, 2 Minor.
  Reviewer verified every constraint by running it rather than reading: the cv_services_* triggers have
  NO WHEN clause and name no columns, so a new column replicates automatically (and deleting `mac` from
  the schema makes the config-version test fail, so that is pinned); the snapshot path carries the MAC
  end to end through Snapshot -> SnapshotInput -> ApplySnapshot -> replaceAll -> putService; and the two
  normalizers are byte-identical, which it confirmed by running both over 14 inputs including EUI-64,
  a 20-byte InfiniBand address and Cisco dot-quad. The migration mutation claim was TRUE this time and
  reproduced, and the fresh-database half is pinned separately.
  Both of the implementer's deviations were upheld. The Step 6 deviation is the best work in the task:
  `validateService`'s documented contract is that it never touches the store so import --replace can
  validate a whole document before writing any of it, and `replaceAll` forces `svc.ID = 0`, so the
  brief's `o.ID != svc.ID` self-exclusion would have been false for EVERY imported pair — a document
  reserving one MAC twice would have passed.

Ruling: P9 — carry into Task 4's acceptance, do not fix here. `updateService` rebuilds a service from
the DTO (`toServiceDTO(cur)`, unmarshal the body over it, `fromServiceDTO`), and neither converter has
a MAC field, so `svc.MAC` comes back "" and `putService`'s UPDATE writes it. Same for the import merge
and import-replace paths. Unobservable today because no transport can set a MAC — but the moment Task 4
adds the field, any unrelated PATCH to a service wipes its reservation. Adding the field to
`fromServiceDTO` alone (the write direction the CLI needs) leaves the bug fully in place. Task 4 must
add it to BOTH converters and prove it with a round-trip test: set a MAC, PATCH an unrelated field,
assert the MAC survives. This is the same class as Part 1's `postServerSettings` defect, which also came
from a form rebuilding a whole record from a partial DTO. Cost if wrong: reservations silently erased by
routine service edits — invisible until someone's device stops getting its address.

Task 2: minor (deferred): uniqueness is checked in a separate transaction from the write, with no lock
  anywhere in registry/adminapi/store, so two concurrent admin writes of the same MAC both pass and both
  commit. Bounded — a homelab admin surface, and the effect is a nondeterministic MAC->address map for
  one host until an operator edits it. The cheap close, if ever wanted, is a post-migration
  `CREATE UNIQUE INDEX IF NOT EXISTS ... ON services(mac) WHERE mac != ''` in `Open`; it cannot go in
  `schema` (fails on upgraded databases) or in a migration alone (skipped on fresh ones).
Task 2: minor (deferred): the new migration test is a third fixture where extending
  `TestOpenMigratesAnOlderDatabase` — which starts at user_version 0 and already runs migration 5, and
  is where Task 1's assertions were appended — would have cost two lines. It does buy the incremental
  v5->v6 boundary specifically.
Task 2: fix round 1/5 (1 addressed, 0 open; commits 23cc48c..ee80cba). Re-reviewer ran the mutation
  itself and confirmed the two guards genuinely need separate tests: `PutService` short-circuits on an
  empty MAC before ever calling `macUnique`, so `macUnique`'s own guard is invisible to that path, and
  only `ReplaceAll` calls it unconditionally. One test cannot see both mutations. Also confirmed the new
  test asserts three rows read back, not just a nil return.
Task 2: complete (commits e3737da..ee80cba, review clean)
Task 2b: implemented (commit d11fbcb) — rule 1 gains a three-way tentative split: commit on the ACK
  path, fall through when the reserved address is under someone else's live lease, and otherwise
  "promise" the reservation by returning it uncommitted so the client's current lease is untouched.
Task 2b: review — SPEC ✅ except one line. QUALITY approved, 0 Critical, 1 Important, 3 Minor.
  The reviewer attacked the promise design on six fronts and it held: `free()` and rule 2 both bar a
  reserved address from every other client (confirmed empirically — a second client's Offer, Allocate
  and a third's rule-4 sweep all refused it); `Load()` does not touch the reservation maps so the bar
  survives a restart; a restart with a promise outstanding idempotently re-derives it; the probe-hit
  retry is gated on `fresh` so it can never Release the lease the client is still on; the empty
  Hostname is inert because Offer's Lease has exactly two consumers and both read only .IP. It also
  verified the hoist of `prev, hasPrev` out of the closure cannot go stale, and re-ran 7 of 8 mutants
  with killing test sets matching the report exactly — the first time this function's mutation claim
  has held up.

Ruling: P10 — FIX the residual. The brief's principle was "never destroy a live lease — the client's
own or anyone else's". The promise arm delivers that only when rule 2 will catch the client. When rule
1 falls through AND rule 2 also refuses — the client's current address is reserved to a third MAC, or
out of range — the client lands in rules 3/4 and `commit` deletes its old byIP entry. Reproduced by the
reviewer from a reservation map alone, no restart and no range change, which is exactly what Task 3
supplies: A holds .10 "nas", B holds .11 "backup", reservations {B: .10, C: .11}; one bare DISCOVER
from B and "backup" is gone from DNS, B sitting on a 60s unnamed hold at .12. Against ee80cba the same
input destroyed BOTH leases, so this is a residual rather than a regression — but it is the third
instance of the shape that shipped two Criticals in Part 1, and the report's own concern 3 does not
describe this trigger. Fix: on the tentative path, refuse to move a client that already holds a live
lease. Only clients rule 2 already refused can reach that guard, so it is narrow, and it also closes
the deferred Part 1 shape (b) — a restored lease outside a narrowed range. Cost if wrong: a client
whose reserved address is squatted keeps its current address until it REQUESTs, which is what it was
already doing.

Task 2b: spec defect found — `docs/superpowers/specs/2026-08-19-kydns-builtin-dhcp-design.md:217` says
  "A DHCPDECLINE from a client quarantines it the same way", and that is now false for a promised
  address: `Decline` gates on `a.byIP[ip] != mac` and a promise never writes byIP, so the DECLINE is
  refused, nothing is quarantined, and the log line says the client does not hold the address. Harm is
  low — rule 1 ignores the quarantine list anyway, so the loop pre-dates this change — but the promise
  removes the last mechanism by which an operator learns a reservation points at a squatter.
Task 2b: fix round 1/5 (3 addressed, 1 NEW Important + 1 unpinned mutant; commits d11fbcb..83c3736).
  Both reported survivors were real and are now pinned. The re-reviewer confirmed M8's masking claim
  verbatim by running a three-way matrix — base-src/base-tests KILLED by 3, head-src/those same 3
  SURVIVED, head-src/head-tests KILLED by the new helper-contract test — and then checked whether the
  new guard masks anything else by running nine more mutants against head-src with the pre-fix test
  set. M8 is the only one masked, and coverage actually improved in one place (rule 2's `usable` check
  went from unpinned to pinned). The harness clock change was verified inert two ways: `Server.now` has
  exactly two call sites, no pre-existing test reaches either, and removing both new `Now:` lines
  leaves the package green.

Ruling: P11 — FIX the regression the guard introduced. `alloc.go:172`'s
`if tentative && held { return prev, false, true }` returns `prev.IP` unchecked, while rule 1's
structurally identical arm gates on `!a.protected(ip)`. So a DISCOVER can be OFFERed the server's own
address or the gateway, and the REQUEST for it is then NAKed forever — an unbounded DORA loop.
Reproduced at 83c3736 (`Host=192.168.1.5 offered=192.168.1.5 fresh=false ok=true`), and at d11fbcb the
same input correctly offers .10. This is a regression the fix introduced, not a pre-existing hole.
Reachable without anyone editing a lease file: Config.Host is the interface address and Config.Gateway
the detected default route, so a router swap or an interface renumber turns a legitimately-persisted
lease into a protected one; `restore()` puts it back in byMAC, rule 2's `usable()` refuses it, and the
new guard hands it straight back. Fix is one clause — `&& !a.protected(prev.IP)` — which the reviewer
applied to a scratch copy and confirmed leaves the suite green with shape (b) still closed, because
`protected` is not `usable`. Cost if wrong: none; it restores the check every sibling path already has.

Task 2b: also open — mutant N5 (`held` → `hasPrev` at alloc.go:172) SURVIVES the full suite. Not
  equivalent: with an expired out-of-range holding the unmutated code returns a fresh probed address
  and the mutant returns the stale one unprobed. `held` is the correct choice and the comment says so,
  but nothing pins it. They built the over-application check for `tentative` and none for `held`.

Ruling: P5a — RETRACTS P5's factual claim. P5 said "Task 3 must wire Reservations() into the registry's
existing change callback, and the plan does not say so." The plan does say so, in detail: Task 3's
Step 4 adds `RefreshReservations`, `Problems()`, and the `alloc`/`subnet`/`services`/`problems` fields,
and Step 5 hooks the `registry.New` callback — including declaring `var dhcpRun *dhcpRunner` above the
call so the closure captures it, guarding with `if dhcpRun != nil`, and setting `services: st.Services`.
I ruled on the task's interface summary without reading its steps. The seam identification in P5 was
right and matches what the plan already chose; the "plan does not say so" was wrong and is withdrawn.
That is the second ruling of mine found wrong this run (P3 was the first), both from asserting a fact I
had not actually checked.

Ruling: P12 — the plan's Step 4 instruction "Call `d.RefreshReservations()` at the end of a successful
`Reconcile`" is a DEADLOCK and must not be implemented as written. Verified at HEAD:
`Reconcile` opens with `d.mu.Lock(); defer d.mu.Unlock()` (internal/app/dhcp.go:73-74) and holds the
lock for its whole body, while `RefreshReservations` opens with `d.mu.Lock()`. Go's `sync.Mutex` is not
reentrant, so the call hangs — and `Reconcile` runs at boot from serve.go, so the daemon would never
finish starting. This is the same class as R2a in Part 1: a plan instruction that cannot compile or
cannot run, invisible until someone tries it.
Fix: refresh reservations from a path that does not already hold `d.mu`. The straightforward shape is a
private `refreshLocked()` holding the derived values, called from inside `Reconcile` where the lock is
already held, with the exported `RefreshReservations()` taking the lock and delegating — the standard
Go split this codebase already uses (`stopLocked`). The store read (`d.services()`) must NOT happen
under `d.mu`: it is I/O, and holding a lock across it would block `Status()` and every settings save.
So the shape is: read services outside the lock, then take the lock to publish. The implementer should
work out the exact split and justify it; what is binding is that no path takes `d.mu` twice and no path
holds it across the store read.
Cost if wrong: a deadlock at boot, or a lock held across I/O — both caught by the race detector and a
startup test, which is why Task 3 must have one.
Task 2b: fix round 2/5 (2 addressed, 0 open; commits 83c3736..ff5d6cf). Re-reviewer re-ran all five
  mutants itself, restoring alloc.go byte-identical after each and re-running the whole package: all
  killed, table matches exactly. Confirmed no over-application — the narrowed-range case still passes
  because `protected` and `usable` stay distinct predicates — and traced the protected case through to
  a converging DORA round.
Task 2b: minor (deferred): the guard's returned Lease has its IP pinned but not its Hostname/Expires —
  mutating those on the return path survives, because the round-1 tests check them against
  `a.Leases()` (proving the guard did not commit) rather than against the value `Offer()` returned.
  Inert today: `offer()` reads only `l.IP`, and `reply()` uses `Cfg.LeaseTime` not `l.Expires`. Worth
  knowing for any future caller of `Allocator.Offer` that reads more than the address.
Task 2b: complete (commits ee80cba..ff5d6cf, review clean after 2 fix rounds)
Task 3: implemented (commit 30176d7) — dhcpd.Reservations resolver, RefreshReservations/Problems on the
  runner, registry callback hook.
Task 3: review — SPEC ✅. QUALITY not approved: 0 Critical, 4 Important, 7 Minor.
  P12 was resolved correctly and PROVED: the reviewer re-introduced the brief's Step 4 wiring in a
  scratch tree and watched the package hang at 90s with RefreshReservations blocked beneath reconcile.
  The implementer's `ranWithin` helper turns that class of regression into a 5s failure instead of a CI
  hang — good call. The implementer also caught a defect the brief never mentioned: `stopLocked` runs
  AFTER `build`, so the brief's `d.alloc, d.subnet = ...` inside `build` would have been cleared
  immediately and RefreshReservations would have returned early FOREVER — the feature would have
  shipped permanently inert with a green suite. Reviewer reproduced that too.
  Four Importants, each proven by running it, not argued:
  (1) reserve.go:64-67 — the registry enforces MAC uniqueness but NOT address uniqueness, so two
      services at one in-subnet address with different MACs is a permitted state. Both MACs map to the
      same address, `problems` is empty, both clients are allocated it, and `commit` deletes the first
      client's lease while the device keeps using the address. Two devices on one IP, silently.
  (2) reserve.go:33,45,66 — MACs are keyed and compared unnormalized. The registry normalizes on write,
      but the replica path writes services straight to the store with no validation
      (`internal/replica/puller.go:56-61` -> ApplySnapshot). `AA-BB-CC-DD-EE-FF` at .20 and
      `aa:bb:cc:dd:ee:ff` at .21 are not flagged as duplicates, and the legacy device was handed .21 —
      the OTHER service's address.
  (3) dhcp.go:324-347 — two overlapping refreshes have no sequence number, so an older service list can
      win and stick until the next registry write. Reviewer validated a fix (a `gen uint64` bumped under
      d.mu and re-checked alongside the existing `d.alloc != alloc` guard, with SetReservations moved
      inside that critical section) and separately proved the smaller-looking `refreshMu` fix DEADLOCKS
      the stop-during-refresh test.
  (4) dhcp.go:130-134 — the single assignment the whole feature depends on has no test. Applying the
      brief's broken placement leaves the entire internal/app package green.
Task 3: fix round 1/5 (5 addressed, 2 surviving mutants; commits 30176d7..8b8c28d). Re-reviewer
  re-ran all 7 of the round's mutants (all reproduced as reported) plus 4 of its own, and verified the
  hardest question — how Findings 3 and 5 interact — by pointer identity rather than by argument:
  `b.alloc` is created inside `build` under d.mu, seeded, and published to `d.alloc` in the SAME
  critical section, so any refresh holding it must have taken the lock after the seed and can never
  carry an older list, while any refresh holding the previous allocator fails the `d.alloc != alloc`
  check. The seed deliberately does not bump `gen`, correctly, because it targets an allocator no other
  goroutine can see. Confirmed alloc.go untouched, `Reservations` still pure, no lock inversion, and
  nothing holding d.mu across a store read.
  It also scrutinised the one edited test and found the guard NOT weakened on the defect it covers —
  the relative read-count assertion still fails when the store read moves above the early return — and
  judged the `start func(built) error` hook shape sound rather than leaky, since `built` is exactly the
  value `reconcile` already holds and the brief's shape would have required exporting an allocator
  accessor on `dhcpd.Server`.

Ruling: P13 — close both surviving mutants rather than deferring them. Neither is a behaviour defect;
both are guards that are correct today and unpinned, which is precisely the shape that produced Part 1's
Criticals — a guard deleted later because it read as redundant, with a green suite.
  M8: dropping `d.alloc != alloc` while keeping `d.gen != gen` survives the whole internal/app suite.
      The guard is load-bearing and reachable: `reconcile` changes `d.alloc` WITHOUT bumping `gen`, and
      the bump happens only in the `RefreshReservations` that `Reconcile` calls afterwards — so an
      in-flight refresh taking d.mu in that window has an equal `gen` and a dead `alloc`. The reviewer
      proved it with a temporary test that fails under the mutant and passes unmutated under -race.
  M11: the `if start == nil { start = startListener }` nil-default introduced by Finding 4's own fix is
      itself unreachable by any test — `serve.go` never sets the field, so deleting those two lines is a
      nil-func panic at boot on every DHCP-enabled node, suite green. Same defect class as the finding
      that created it.
Cost if wrong: two tests.

## Task 4 pre-dispatch verification (controller; do not re-derive)

Ruling: P14 — Task 4's file references are stale. `internal/adminapi/services.go` does not exist. At
HEAD: `serviceDTO` is `internal/adminapi/api.go:121`, `toServiceDTO` at `:401`, `fromServiceDTO` at
`:412`. `WithDHCP` and `getDHCPStatus` are in `internal/adminapi/dhcp.go` (created by Part 1's Task 11),
the route is registered at `api.go:242`, the provider field is `dhcpStatus func() (bool, error)` at
`api.go:36`, and serve.go wires it at `:304`. Cost if wrong: an implementer creating a file that should
not exist and leaving the real DTO untouched.

Ruling: P15 — the `mac` field on `serviceDTO` needs a **yaml tag as well as a json tag**. The brief says
only `json:"mac"`. Every sibling field on that struct carries both (`api.go:121-130`), because
`serviceDTO` is the export/import shape — this is exactly the hazard Part 1's R32 documents: a field
with no yaml tag falls back to its lowercased Go name instead of its snake_case json name and is
silently blanked on every settings import. A reservation that survives a save and vanishes on an import
is worse than one that never saved. Use `json:"mac,omitempty" yaml:"mac,omitempty"` to match the
neighbouring optional fields, and prove it with an export→import round trip, the same way Task 1 proved
`dhcp_allow_foreign`. Cost if wrong: none; it matches every sibling.

Ruling: P2a — restates P2 now that Task 4 is next. The brief writes a NEW handler
`func (a *API) dhcpStatus` and a new type `DHCPStatusFull`, but Part 1 already ships
`getDHCPStatus` on the same route `GET /api/v1/dhcp/status`. Task 4 must WIDEN the existing handler and
its provider, not register a second one — two handlers on one route is a `mux` panic at startup, and a
parallel type would leave the codebase with two shapes for one endpoint. The provider must change from
`WithDHCP(status func() (bool, error))` to something that can also carry foreign servers, reservation
problems, supported/reason and dual-stack; the runner already exposes `Status()`, `Foreign()` and
`Problems()`. Part 1's existing tests for the endpoint must be extended, not duplicated.
Task 3: fix round 2/5 (2 addressed, 0 open; commits 8b8c28d..467a35d). Re-reviewer ran all four mutants
  and confirmed M3 and M8 are now killed by DISJOINT test sets, which is what proves the two halves of
  the staleness guard are independently pinned rather than one masking the other. It also judged the
  reflect-based M11 test sound and non-vacuous: under the mutant a typed-nil func's `.Pointer()` is 0
  and compares cleanly unequal, so the test fails with its intended message rather than panicking, and
  `effectiveStart()` is a pure extraction called by production code, not a test-shaped seam.
Task 3: complete (commits ff5d6cf..467a35d, review clean after 2 fix rounds)
Task 4: implemented (commit 6a002ac) — widened DHCP status endpoint, wizard prefill, service MAC through
  both DTO directions, CLI keys, and a new `service update` command.
Task 4: review — SPEC ✅. QUALITY approved, 0 Critical, 1 Important, 4 Minor.
  P9 confirmed fully fixed and the half-fix reproduced: mutating either converter fails
  `TestServiceMACRoundTripsThroughTheAPI` and `TestPatchDoesNotEraseTheMAC`. The reviewer also verified
  the []-not-null contract three ways (nil runner, runner returning nil slices, runner returning empty
  slices), confirmed the nil-provider contract still holds because `newAPI(t)` never calls `WithDHCP`,
  and ran a malformed MAC through both POST and PATCH to confirm a field-addressable 400.
  It judged the interface-shaped provider sound: `WithReplication` is func-shaped only because adminapi
  cannot import `internal/app`, and that constraint does not apply to `internal/dhcpd`, which adminapi
  must now import anyway. It also credited two catches the brief missed — `addrText` for
  `netip.Addr{}.String()` returning "invalid IP", and an `a.settings != nil` guard for a latent panic in
  the brief's own snippet.

Ruling: P15a — CORRECTS P15's justification. P15 said the `mac` field needed a yaml tag because without
one it "falls back to its lowercased Go name instead of its snake_case json name and is silently blanked
on import". For THIS field that is false: the Go name is `MAC`, yaml.v3 lowercases it to `mac`, and that
is already the right key. The reviewer proved it — deleting the yaml tag on a scratch copy leaves the
round-trip test green, including its export assertion. The tag is still correct and should stay, because
every sibling has one and consistency is worth more than the byte, but my stated reason did not apply
here and R32's real victims are fields whose lowercased Go name differs from their json tag, like
`check_url`. That is the third ruling of mine this run whose factual claim was wrong (P3, P5, now P15) —
all three from asserting a mechanism I had not tested on the specific case in front of me.
Consequence: the comment the implementer wrote at api.go:130-132 repeats my wrong reason and should be
corrected, and the tag is unpinned by any test.

## Task 5 pre-dispatch verification (controller; do not re-derive)

Ruling: P16 — Task 5's DHCP tab reads its data through an exported accessor on `adminapi.API`, and
Task 5 must add one because Task 4 did not. The brief leaves the choice open ("the API handlers from
Task 4, or the same underlying components — follow whichever the existing pages do"). The existing
pages settle it: `internal/web` imports `adminapi` and holds `API *adminapi.API` in its Options
(`middleware.go:26`), and every page that needs something the API already computes calls an exported
method guarded by `s.o.API == nil` — `ReplicaRows()` (`replication.go:59`), `CanPair()` (`:119`),
`InviteReplica()` (`:139`), `WriteExport()` (`settings.go:186`). Pages that need raw store data use the
components directly instead (`blacklists.go` imports only `store`).
DHCP status is computed data, not raw rows — supported/reason come from `Qualifies`/`Inspect`, and
foreign/problems come from the runner — so it belongs on the API side. `adminapi` currently exposes only
`WithDHCP` (`dhcp.go:21`); `getDHCPStatus` computes everything inline.
Decision: Task 5 extracts the body of `getDHCPStatus` into an exported accessor (the `ReplicaRows()`
shape), leaving the HTTP handler as a thin caller so there is ONE implementation feeding both the JSON
API and the tab. Do not let the tab recompute status from the runner itself — that is the second-shape
drift R13 rejected in Part 1, and it would let the two surfaces disagree about whether DHCP is running.
Cost if wrong: one accessor to rename.

Task 5 also carries, from earlier reviews:
- P7: the four routes take `s.requireSession(...)` for the GET and `s.requireCSRF(...)` for the three
  POSTs (`internal/web/pages.go:18` onward is the pattern). The plan lists them bare, and an unwrapped
  POST here would let any origin change DHCP settings or plant a reservation.
- P6: `POST /dhcp/reserve` reuses the existing promote-to-service flow rather than adding a parallel
  one. The spec says the Reserve button "promotes a lease to a service with its MAC and address filled
  in, reusing the existing promote-to-service flow", and Part 1 ships that flow twice already —
  `internal/web/discovered.go` `postPromote` and `POST /api/v1/leases/{ip}/promote`. The genuinely new
  part is carrying the MAC through, which the existing flow drops.
- From Task 4's review: `supported: false` with an empty `reason` is the "no interface chosen yet"
  state and must NOT render as a blank error box; and `supported: true` can still disagree with a 400
  from `/suggest` on a subnet smaller than /29, so the tab must render the suggest error rather than
  trusting the flag alone.
- From Task 4's report: `getDHCPStatus` calls `Qualifies`/`Inspect` per request — `/sys` and `/proc`
  reads, no sockets — so the tab must not poll it hard.
Task 4: fix round 1/5 (4 addressed, 0 open; commits 6a002ac..87fc832). The implementer proved Finding 1
  against a real artifact rather than by reasoning: they built the adminapi test binary and ran it inside
  an unprivileged netns holding only `lo` and a dummy 100.64.1.5/32 interface — the old helper picked it
  and the test failed with a genuine 400; the new one found nothing and skipped. Host untouched.
  Re-reviewer checked the risk I cared about most — whether the fix over-applies and silently disables
  the test everywhere — and confirmed it does not: `SuggestRange` rejects only non-IPv4 and bits > 29, so
  any real LAN passes, and the new helper continues past a too-small interface instead of
  short-circuiting on the first `Qualifies` hit, which is strictly more permissive. It also confirmed the
  test-helper's call sequence is byte-for-byte the production handler's, so the two cannot drift.
  Finding 2's mutant killed. Finding 3 confirmed non-pinnable by deleting the tag and watching the
  round-trip stay green — P15a stands.
Task 4: complete (commits 467a35d..87fc832, review clean)
Task 5: implemented (commit b52d1d9) — the DHCP tab, DHCPStatus/DHCPSuggest accessors, promote extended
  to carry the MAC.
Task 5: review — SPEC ❌ on one point. QUALITY not approved: 0 Critical, 3 Important, 5 Minor.
  All three rulings met in substance. The reviewer verified the security-sensitive surface by EXECUTION,
  not reading: it swept every registered POST route and confirmed each returns 403 with a session but no
  CSRF token, that anonymous POSTs to all three /dhcp routes redirect to /login with the setting
  unchanged, and that a malformed, foreign-segment or lease-less `ip` on /dhcp/reserve all fall through
  to a 400. It also rendered /dhcp on a replica (200, Save disabled, no template error) and confirmed
  `dhcpd.Qualifies` calls `net.InterfaceByName` before the sysfs read, so an operator-supplied interface
  name cannot traverse into /sys.
  It judged the second accessor (DHCPSuggest) warranted rather than scope creep — the tab needs the
  identical Qualifies/Inspect/SuggestRange chain and writing it again in internal/web is exactly the
  second-shape drift P16 rejects — and confirmed no existing test was weakened, checking every `-` line.
  It also credited the dropped hidden mac/hostname fields as a real security improvement with no spec
  loss: it removes a "reserve any MAC to any name at any address" primitive that an admin-authenticated
  XSS or a stale form could drive.

Ruling: P17 — FIX the promote regression. `discovered.go:107` attaches `MAC: l.MAC` unconditionally, so
every promote now runs `ValidateMAC` and `macUnique`, which never ran on that path before. Proven by the
reviewer against BOTH commits:
  (a) a dnsmasq lease file that also holds DHCPv6 leases puts the IAID, not a MAC, in field 1, and
      `internal/discovery/dhcp/dnsmasq.go:108` takes fields[1] verbatim with no IPv4 filter anywhere in
      internal/discovery. Promoting {printer, 192.168.1.51, MAC:"163461164"} was 303-and-created at
      87fc832 and is 400-and-nothing at b52d1d9.
  (b) two leases sharing one MAC (one device, two hostnames) was 303,303 at base and is 303,400 at head.
The implementer's report argued the change is safe because the validator refuses a lease file and the
built-in server at once — that covers whether the MAC is INERT, not whether writing it is REJECTED.
Fix: attach the MAC only when `registry.ValidateMAC(l.MAC) == nil`, and decide deliberately what a
duplicate MAC should do — dropping it and proceeding preserves the old contract; blocking changes it.
Cost if wrong: a promote that used to work keeps working and simply carries no reservation.

Ruling: P18 — the DHCP settings surface is unreachable on a replica through ANY supported path, and that
is a design gap for the whole-branch review, not a Task 5 bug. The web gate refuses the three /dhcp
POSTs (swept by `TestReplicaRefusesEveryPostRoute`), and the report claimed the CLI was the workaround —
the reviewer proved that false: `kydns settings set` PATCHes /api/v1/settings, which `adminapi.WriteGate`
409s on a replica just the same. So an operator cannot pre-configure DHCP on a node before promoting it.
The gate's usual rationale genuinely does not apply here — the reviewer traced `ApplySnapshot` re-reading
all twelve node-local columns including every dhcp_*, so a pull cannot overwrite them. But the spec pins
the contract as "matches how dhcp_lease_file is already treated", and dhcp_lease_file is equally
unsettable on a replica today, so Task 5 is compliant and `webWriteExempt` is pinned by value in a test
on purpose. Not touching it was right. Surfacing the question with correct facts is the deliverable.
Task 5: fix round 1/5 (5 addressed, 0 open; commits b52d1d9..ebd3a03). Re-reviewer confirmed both
  regression shapes now behave as they did at 87fc832, AND checked the trap I was most worried about —
  that a fix which simply stopped attaching MACs entirely would pass both regression tests while gutting
  the feature. It ruled that out by execution: a valid unique MAC still reaches the created service.
  It also confirmed the CSRF sweep is a genuine sweep — `registeredPostRoutes` calls `srv.routes(&rec)`
  against a recording mux, so it enumerates the live router's own registrations rather than a hand list,
  and a future unwrapped route joins it automatically. Proven by registering /dhcp/reserve without
  requireCSRF and watching the sweep catch it.
  The duplicate-MAC decision (drop the MAC, let the promote succeed) was judged defensible with a
  disclosed blind spot: the Discovered screen renders the lease's raw MAC with no indicator, so an
  operator can see a MAC, promote, and get a service without one. Not a new deception — pre-b52d1d9
  promote never wrote a MAC at all, so this restores that exact baseline for the ambiguous case — and
  the implementer disclosed it rather than leaving it implicit.
Task 5: minor (deferred): a dropped MAC is not announced to the operator; there is no flash-message
  channel in this codebase to carry it without new plumbing.
Task 5: minor (deferred): Enter in the settings form runs the wizard rather than Save, because the
  formaction button precedes Save. Nothing is written, but a hand-typed range is replaced.
Task 5: minor (deferred): Reserve creates but never updates, so a name collision reports "duplicate
  name". Reusing the existing flow was the correct reading of P6 over the brief's "create or update".
Task 5: complete (commits 87fc832..ebd3a03, review clean)
Task 6: implemented (commit c71327b) — README, DESGINE, SECURITY, both design docs, AGENTS,
  kydns.example.yaml.
Task 6: review — SPEC ✅. QUALITY approved, 1 Critical (inherited), 1 Important, 8 Minor.
  The reviewer verified roughly thirty operator-facing claims line by line against the code and found
  every one true at HEAD. It went further than the report on one: the "ordinary packet exchange is not
  logged" claim also depends on the LIBRARY's logger, and it checked that `server4.NewServer` is called
  with no ServerOpt so it keeps EmptyLogger and suppresses its own per-request lines.
  It credited the implementer for following the SPEC over the brief where the two disagreed — my brief
  drafted "malformed packets are counted and dropped", which Part 1 had already corrected to "not
  counted", and shipping it would have put a false claim in SECURITY.md.

Ruling: P19 — I was wrong about `private_domain`, and the implementer was right to refuse the edit. My
Task 6 brief said the settings design doc still documented it as requiring a restart. It did not:
`git show ebd3a03:...2026-08-13-kydns-settings-in-the-ui-design.md` already read "private_domain is
applied live too" at :45, "Nothing requires a restart today" at :47, and "Nothing produces it today" at
:193 — all fixed by Part 1's cc8ac96. I was reading the state as of when I recorded the item, not as of
the branch. Brief Step 2 was likewise already done. That is the FOURTH ruling of mine corrected by an
implementer this run (P3, P5, P15, now P19), and the fourth time the cause was asserting a fact I had
not re-checked against the current tree.

Ruling: P20 — `SECURITY.md:130` is a Critical that Task 6 inherited rather than caused, and it gets
fixed anyway. "Linked-server replication is designed but not implemented" is false: `internal/replica`
ships the pinned TLS transport, the pairing exchange and the pull loop, README documents the operator
workflow, and DESGINE describes it as built. `:133-134` compounds it — "the design permits concurrent
writers with deterministic last-write-wins" contradicts DESGINE's "exactly one primary". A reader
assessing this deployment concludes replication is not attackable because it does not exist, which is
the worst failure mode a security document has. The implementer disclosed it and declined the full
rewrite; declining the rewrite was right, leaving the four false words was not. The minimal fix does not
require auditing the section's other claims. Cost if wrong: a security document that describes the
software that actually shipped.

Ruling: P21 — the spec's "no metrics surface for a single number to land in" is MY error and gets
corrected. I wrote that justification when ruling to amend rather than build the malformed-packet
counter, and it is false: `internal/adminapi/api.go:250` registers `GET /api/v1/stats`, which already
aggregates query, ACL-refusal, cache and per-list block counters. The operative decision — not counted —
stands and the user chose it; only my stated reason was wrong. Fix the spec, since SECURITY.md inherited
the wording verbatim from it. Cost if wrong: none; the decision is unchanged.
Task 6: fix round 1/5 (4 addressed, 0 open; commits c71327b..070a52e). Re-reviewer checked every claim
  the REWRITTEN SECURITY.md replication section makes — a new false claim in a security document would
  be worse than the one it replaced — and found all six true against internal/replica and internal/store:
  TLS 1.3 with a pinned fingerprint and no CA path, the one-time pairing code with nothing written to a
  declined peer, the whole-config pull in one transaction, the never-replicated set, single-writer
  enforcement in both gates, and stale-rather-than-wrong. It judged the rewrite minimal — one paragraph
  for one paragraph — and verified both lines the implementer deliberately left alone are genuinely
  fine: AGENTS.md:50 describes a specific older spec's own scope, and the replication spec's
  last-write-wins line sits under "Departures from the deferred sketch" describing the REJECTED design.
  The implementer also found the same false replication claim in AGENTS.md:43 while sweeping — the index
  that tells the next agent what each document means — and corrected it.
Task 6: minor (deferred): SECURITY.md:37-41 says "only the exceptions are" and enumerates six, but
  `internal/dhcpd/server.go:350` logs an IP during ordinary packet handling when a probe hits. Defensible
  as omitted since it names no MAC, but a strict reading of "only" does not cover it.
Task 6: complete (commits ebd3a03..070a52e, review clean)

## All 7 tasks complete (1, 2, 2b, 3, 4, 5, 6). Whole-branch review next.

## Whole-branch review (e0662c9..070a52e, 16 commits)

Reviewed in seven passes on the most capable model. Verdict: ready to merge WITH FIXES.
0 Critical, 3 Important, 6 Minor. Findings written to final-findings.md for the fix wave.
Six of seven safety properties are kept AND pinned by tests; the seventh — no raw sockets,
CAP_NET_BIND_SERVICE only — is kept but untested, because no test reads packaging/kydns.service, so a
future edit adding CAP_NET_RAW would ship green.
The reviewer re-derived P8, P10, P11, P12, P13 and P17 against the code and found every DECISION sound.
It found a FIFTH incorrect factual claim in my rulings — see P4a.

Ruling: P4a — CORRECTS P4's justification. P4 said "Part 1's R17 already made both parse via
net.ParseMAC and re-render, so dash, Cisco dot-quad and unpadded forms converge". Dash and dot-quad do.
**Unpadded does not**: `net.ParseMAC("a:b:c:d:e:f")` returns an error, and both packages fall back to a
lowercased copy. The operative decision — two normalizers with byte-identical bodies, pinned by a shared
test table — is right, and the implementers' test tables documented the real behaviour correctly. Only my
justification was false, and it propagated into two production comments, which the fix wave corrects.
That is the fifth ruling of mine this run whose factual claim was wrong (P3, P5, P15, P19, now P4), and
the fifth time the cause was asserting a mechanism I had not tested on the case in front of me. The
pattern is consistent enough to be worth stating plainly in the handoff.

Ruling: P22 — OPERATOR DECISION, not mine: exempt `dhcp.*` from the replica write gate. I put the three
options to the operator with their costs and they chose to restore the spec's promise rather than amend
it. The gate's own rationale supports it — the gate refuses edits because the next pull discards them,
and P18's reviewer traced that a pull provably CANNOT discard these twelve node-local columns, since
`ApplySnapshot` re-reads them out of the local row before writing.
This is a security-sensitive loosening and gets its own task and its own review rather than being folded
into the running fix wave. Binding constraints for that task:
  - The exemption must be scoped to DHCP settings ONLY. `PATCH /api/v1/settings` is a partial update over
    the whole row, so exempting the endpoint wholesale would let a replica change anything — that is the
    defect to avoid, not the goal.
  - Preferred shape: exempt the path in both gates, and enforce the narrowing in the settings write path —
    on a replica, a write may change `dhcp_*` fields and nothing else, rejected with the existing
    read-only-replica error otherwise. The gate decides reachability; the handler decides scope.
  - The web side's three `/dhcp/*` POSTs are structurally DHCP-only already (Task 5's `apply` reads
    current settings and overlays only the DHCP form fields) — verify that before relying on it.
  - `TestEveryPostRouteRequiresSessionAndCSRF` and `TestReplicaRefusesEveryPostRoute` both sweep the live
    router. The second will need the exemption expressed where the sweep can see it, and
    `webWriteExempt` is pinned by value in a test on purpose — that test is the record of what is
    reachable on a replica and must be updated deliberately, not worked around.
  - A replica still must never START the listener. `dhcpWanted`'s `role != RoleReplica` gate is untouched;
    this changes only what can be CONFIGURED, not what runs.
Cost if wrong: a replica can be reconfigured for DHCP by anyone who can already authenticate to it as an
admin — which is the same authority that can already promote it.

Ruling: P22a — amends P22 with a constraint I found while verifying its premise. `/dhcp/settings` IS
structurally DHCP-only: `dhcpForm.apply` (internal/web/dhcp.go) takes the current settings and overlays
exactly the eight `DHCP*` fields, leaving everything else as read. Verified. So the web-side exemption is
safe by construction.
BUT it is a read-modify-write over the WHOLE row — `s.liveSettings()` then `Settings.Set(form.apply(cur))`
— and on a replica that window matters more than anywhere else in the codebase, because a pull can land
in it continuously rather than only when an admin is typing. If one does, the write reverts the
just-pulled non-DHCP values to whatever the replica held a moment earlier. That is the same
read-modify-write hazard Part 1's Task 11 review recorded for `postServerSettings`, but on a replica it
is no longer a narrow race between two admins; it is a race against the background puller.
Constraint for the P22 task: on a replica the DHCP settings write must not write back non-DHCP fields at
all. That points at a narrow store-level write — the `dhcp_*` columns only — rather than a whole-row
`Settings.Set`. Whoever implements it should weigh that against the cost of a second write path, and say
which they chose and why. If they keep the whole-row write, they must show the pull race is either
impossible or harmless, not assume it.
Cost if wrong: a replica's pulled configuration silently rolls back by one pull interval when an operator
saves DHCP settings — invisible until someone notices a setting reverted.
Fix wave (commits 070a52e..fc6839a): all seven findings fixed. I1 resolved by REFUSING the build on a
seed read error rather than annotating it — the implementer's reasoning: a synthetic ReservationProblem
only labels the demonstrated wrong-address outcome instead of preventing it, and the outage cost is small
because the refusal sits AFTER the unchanged-config early return and BEFORE `build`, whose
build-before-stop rule already leaves a running listener alone. So only a store error at boot or on an
interface change can refuse a start. Mutation: I1 (both seed branches plus the refresh branch), I2, M1
and M3 all reverted and confirmed failing, no survivors.

Ruling: P4b — a SIXTH correction, and this one is in my findings list rather than a ruling. M2 in
final-findings.md said the false "without zero-padding ... still compares equal" claim appears in two
comments. It appears in ONE — `internal/dhcpd/server.go:452`. `internal/registry/validate.go`'s
`NormalizeMAC` comment makes no zero-padding claim at all; it says only "lowercase, colon-separated" and
that its body matches dhcpd's, both of which are true. The implementer verified by grep over internal/
(one hit) and by executing net.ParseMAC on all four spellings, and correctly changed nothing there.
I had propagated my own P4 error into the findings list without re-checking the second site.
They also noticed that M2's surviving TRUE claim ("no separators at all") was itself unpinned, and added
a table row to `TestNormalizeMAC` in both packages — which is the right instinct: the fix for a false
comment is not just deleting words, it is pinning whatever remains.
Fix wave re-review: All findings addressed, no new Critical/Important breakage. Ready to merge.
  The re-reviewer tested I1's reasoning against the code rather than the prose and confirmed all three
  claims: the refusal is genuinely after the unchanged-config early return (all four entries into
  `reconcile` traced), a store error on a settings save CANNOT take down a working listener because
  `d.fail` never calls `stopLocked`, and the operator sees a legible reason through Status -> DHCPStatus
  -> StartError -> the tab. It called the refusal a strict improvement: the old code would have replaced
  a working listener with one seeded {}. Six mutants run, all killed, including the previously-surviving
  I2 one. It also confirmed the implementer's correction to my findings list was right, and that the new
  TestNormalizeMAC row genuinely discriminates (mutating both normalizers to skip separator-less input
  fails on exactly that row and no other).
Fix wave: minor (deferred): the role snapshot is now taken outside d.mu, so a settings save that reads
  RoleReplica, is descheduled, and loses a full promotion race would leave DHCP down on a promoted
  primary until the next save. Same apply-vs-promote race family already recorded as pre-existing; no
  I/O in the window; the hoist itself is necessary, because two independent d.role() calls would let the
  skip say "off" while reconcile says "on" and reintroduce I1.
Fix wave: minor (deferred): `broadcastOf` pulls `net` into reserve.go for one `net.CIDRMask` call that
  is derivable from `p.Bits()`.

## Task 7 review (fc6839a..3078abf) — the replica gate exemption

Verdict: Approved, ready to merge with fixes. No Critical. The reviewer failed to escalate across
sixteen payload shapes, six route/method/spelling variants and three path-normalisation attempts, and
found the structural reason why: the gate decides reachability, `settings.Service.Set` decides scope,
and `store.PutDHCPSettings` names eight columns in one UPDATE so it physically cannot write a ninth.
With the scope check fully removed (mutant M1) the invariant STILL holds. Two independent barriers,
one mutant killed against each. Twelve mutants re-run, eleven killed, one survivor (P24 below).
The reviewer also verified P22a's premise against the code rather than the prose — `replicaApplier.Apply`
does commit `ApplySnapshot` before `settings.Rebuild()` — and found the narrow write SAFER than the
implementer argued: `store.Open` sets `SetMaxOpenConns(1)`, so `ApplySnapshot`'s transaction holds the
only connection and `PutDHCPSettings` cannot interleave between its SELECT and its `putSettings`.

Ruling: P23 — fix the refusal message to name the primary. `writeSettingsErr` emits
`ErrReadOnlyReplica.Error()`, which says "must be changed on its primary" with no address, while the
gate it replaces for this endpoint says "make this change on 10.0.0.2:8443". The deleted test's second
assertion pinned exactly this and nothing replaced it. This is not cosmetic: README:118 and README:428
both promise the address, `internal/cli/replica_test.go:206` shows the CLI prints the message verbatim,
and this is the one endpoint most likely to be hit during a failover.
Cost if wrong: an operator mid-failover is told to go to "its primary" and not which box that is, by the
one refusal our own documentation says will tell them.

Ruling: P24 — fix `TestTheDHCPFormIsEditableOnAReplicaButReserveIsNot`, which does not test Reserve. It
loops over `">Save<"` and `">Fill in from this interface<"` only, and the Reserve button is inside the
lease-row loop, so in a fixture with an empty lease table it is never rendered — the assertion is
structurally unreachable. Dropping `{{template "ro" $}}` from `templates/dhcp.html:105` survives the
whole `internal/web` package. Nothing is exploitable, because `TestReserveIsStillRefusedOnAReplica`
proves the POST is still 409'd. But this task's entire premise is that the gate tests are the record,
and a test name asserting coverage it does not have is the wrong kind of record.
Cost if wrong: the one control this loosening deliberately left closed is unpinned in the UI layer, and
named as if it were pinned.

Ruling: P25 — make `settings.NewService`'s nil `isReplica` fail CLOSED, not open. Today nil means "writes
freely". It is the security chokepoint for the whole loosening, and its default points the unsafe way:
a future call site that forgets the argument gets a silent hole, where fail-closed gets a loud, immediate
test failure. Only three or four test sites pass nil, so the churn is affordable — each states
`func() bool { return false }` explicitly, which is the point. Global instruction: default to the most
secure option we can reasonably provide.
Cost if wrong: one forgotten argument, years from now, reopens the exemption to the entire settings row.

Ruling: P26 — de-circularise `TestTheReplicaWriteTouchesOnlyTheDHCPColumns`, which asserts using
`dhcpOnlyChange`, the function under test, so M1 does not kill it. Compare with `reflect.DeepEqual`
directly. The property is genuinely pinned by `store.TestPutDHCPSettingsTouchesOnlyTheDHCPColumns`, so
nothing is unpinned — but a circular test reads as if it proves more than it does.

Ruling: P27 — assert against the store, not the holder, in
`TestAReplicaCannotSmuggleANonDHCPKeyIntoADHCPPatch` and `TestSuggestOnAReplicaAnswersAndWritesNothing`.
Both read `svc.Get()`, the in-memory holder, so a partial write that reaches the database and still
returns the error (mutant MX2) leaves the whole `adminapi` package green. Reading through
`store.Settings()` makes the API-level test independent evidence rather than a restatement of the holder.

Ruling: P28 — answer 409, not 400, on `internal/web/dhcp.go`'s spurious-refusal path, so the two
transports agree on the status for the same refusal.

Ruling: P29 — rewrap the SECURITY.md sentence to the file's ~76 columns.

Deferred, recorded not fixed: none from this review.

Task 7 fix round (3078abf..f350356): all seven fixed, re-review Approved, ready to merge. Six mutants
re-run by the re-reviewer, all killed by named tests. It confirmed the gate's message is byte-identical
after the refactor, that no production site passes a nil `isReplica`, and that the variadic `replicaWeb`
left every zero-arg caller unchanged. It also verified the implementer's claim that fix 6's branch is
UNREACHABLE from a handler test — `liveSettings()` and `Set` read the same holder inside one request
with only `form.apply(cur)` between them, and `Set` reads `prev` before calling `isReplica()`, so even a
role closure is too late — and agreed that testing at the function was the honest choice rather than
staging a race. The implementer found a FIFTH nil call site the review had missed
(`adminapi/settings_test.go:417`) and reported it.

Ruling: P30 — the two re-review minors folded in myself (84def9c) rather than spending another round,
because both are three-line changes and both are the change failing to tell the truth, which is this
task's whole subject.
  - An unpaired replica knows no address, and the settings refusal already ends "on its primary", so
    appending the gate's placeholder made it say so twice and carry nothing. `ManagedOn` now returns
    the clause only when there is an address; the gate keeps its placeholder, because there the
    sentence is the whole message and stands alone.
  - The web transport held a COPY of the gate's wording rather than the gate's function, so the two
    could drift apart with both packages green — precisely what the comment above the parity test says
    cannot happen. `ManagedOn` is exported and web calls it, so there is no second copy left.
Proven by mutation in a scratch copy, not by reasoning: `ManagedOn` always appending is killed by
`TestTheRefusalSaysWhereOnceWhenItKnowsNoAddress` (adminapi) and `TestTheDHCPSaveRefusalMatchesTheAPI`
(web); wording drift in `makeThisChangeOn` is killed by the same adminapi test. That second mutant
survived the ENTIRE tree before this commit — including `writegate_test.go:381`, whose `strings.Contains`
happily matches a prefixed variant. The new assertion is exact equality, which is why it catches it.
Note the honest limit: mutant G still survives `internal/web` alone, and that is now correct rather
than drift — web calls the real helper, so there is no copy to disagree with. The wording is pinned
once, in the package that owns it.

Ruling: P31 — closed the outstanding P4/P4a correction in the two planning documents rather than leaving
it recorded-but-unfixed. `plans/2026-08-19-kydns-builtin-dhcp-part2.md` and
`plans/2026-08-20-kydns-builtin-dhcp-part1-handoff.md` both claimed R17 made missing zero-padding
converge. It does not. Added a dated correction to each rather than rewriting the original sentence,
because these are a record of what was planned and believed at the time.
Re-proven by execution before writing the correction, not carried over from my earlier note:
`net.ParseMAC` accepts `aa-bb-cc-dd-ee-ff`, `aabb.ccdd.eeff` and `aabbccddeeff` — all three render as
`aa:bb:cc:dd:ee:ff` — and REJECTS `a:b:c:d:e:f` with "invalid MAC address". So the handoff's "no
separators" case was genuinely fixed by R17 and only the unpadded case was not; the correction names
only that one. A rejected MAC yields the empty string from both normalizers, so the reservation is
refused rather than silently mismatched — the safe direction, but not what the documents claimed.

Part 2 is code-complete: tasks 1-7 done, whole-branch review and its fix wave done, Task 7 and its fix
round done. 19 packages green, vet clean, at 84def9c.
