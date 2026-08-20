# SDD ledger — plan: docs/superpowers/plans/2026-08-19-kydns-builtin-dhcp-part1.md

Spec: docs/superpowers/specs/2026-08-19-kydns-builtin-dhcp-design.md (read; binding authority)
Worktree: .claude/worktrees/dhcp-part1, branch worktree-dhcp-part1, base 7dc7027
Baseline: 18 packages ok, 0 failures, vet clean (after 7dc7027 fixed a pre-existing red test on main)

## Pre-flight scan

### Pairwise (tasks sharing a file or interface)

| A → B | A produces | B consumes | Found |
|---|---|---|---|
| T2 → T3 | `store.DHCPLease` | same | OK |
| T2 → T9 | `Settings.DHCP*` fields | validation rules | OK |
| T2 → T10/T11 | same fields | runner + DTO | OK |
| T3 → T7 | `DHCPLeases/PutDHCPLease/DeleteDHCPLease/DeleteExpiredDHCPLeases` | `LeaseStore` iface | OK — signatures match exactly |
| T4 → T7 | `IfaceInfo{Name,Addr,Subnet,Gateway,HasGlobalIPv6}` | `Options.Iface` | OK |
| T4 → T10 | `Qualifies`, `Inspect` | `build()` | OK |
| T4 → T9 | `SuggestRange` output | range validation | **CONFLICT — see R4** |
| T5 → T7 | `Allocator` methods | packet path | OK, except `Reconfigure` never consumed — **R5** |
| T6 → T7 | `Prober`, `nopProber` | `Options.Prober` | OK |
| T8 → T10 | `DetectForeign(ctx,iface,wait,self)` | `build()` | OK |
| T9 → T10 | validated settings | `netip.MustParseAddr` | **CONFLICT — see R6** |
| T1 → T10 | `SetSource`, nil-tolerant `NewPoller` | always-on poller | OK |
| T10 → T11 | `dhcpRunner.Status()` | `API.DHCP` iface | OK |

### Self-consistency (per task)

| Task | Found |
|---|---|
| T1 | OK |
| T2 | **DEFECT** — test compares `got != v`; `store.Settings` holds `[]string` and is not comparable. Verified: `vet: struct containing []string cannot be compared`. **R3** |
| T3 | OK — `DHCPLease` is all comparable fields, `!=` is valid there |
| T4 | OK |
| T5 | OK; unused `Reconfigure` — **R5** |
| T6 | OK |
| T7 | OK. Minor: comment says renewals are not probed, but the probe is gated on `!commit`, i.e. OFFER always probes. Comment, not behaviour. Deferred minor. |
| T8 | OK |
| T9 | **DEFECT** — same-/24 rule, see **R4** |
| T10 | **DEFECT ×3** — see **R1**, **R2** |
| T11 | OK — helper names already marked "verify against the package" in the plan |

## Rulings

Ruling: R1 — T10 `dhcpWanted` gates on `role != RoleReplica`, not `role == RolePrimary`. Why: `internal/app/role.go:15-19` has THREE roles, and `RoleStandalone` is the normal single-node deployment the README describes; requiring primary would mean DHCP never runs for most users. `serve.go:237` already uses the `!= RoleReplica` idiom for the same "replicas are the exception" reason. The spec says "a replica never serves DHCP", which this satisfies exactly. Cost if wrong: a standalone node serves DHCP where someone expected primaries only — same single machine, no conflict risk.

Ruling: R2 — T10 reads the role via `roleHolder.Current()` (not `.Role()`, which does not exist), and the `dhcpRunner` is constructed after `roleHolder` at `serve.go:213`. `var dhcpRun *dhcpRunner` is declared before `registry.New` so the write callback closure can capture it, matching how `poller` is handled at `serve.go:81`. Cost if wrong: compile error, caught in the same task.

Ruling: R3 — T2's round-trip test uses `reflect.DeepEqual(got, v)`. Why: `store.Settings` contains `[]string` fields, so `==` is a compile error. Cost if wrong: none, mechanical.

Ruling: R4 — T9 drops the "same /24" rule and instead caps the pool at 65536 addresses, keeping `end >= start`. Why: `SuggestRange` takes the upper half of any subnet down to /29, so on a /22 it proposes `x.y.2.0`–`x.y.3.254`, spanning two /24s — the wizard would suggest exactly what the validator rejects. A size cap is subnet-agnostic, so validation still checks only the stored value and never host state. Cost if wrong: an operator on a /22 or wider can configure a very large pool; the lease table is bounded by the range size, and 65536 is the guard.

Ruling: R5 — T5 does not ship `Allocator.Reconfigure`. Why: nothing in Part 1 or Part 2 calls it; `dhcpRunner.Reconcile` rebuilds the server on a config change rather than mutating the allocator. Shipping an unused exported method is the YAGNI violation the review rubric treats as a defect. Cost if wrong: a later change re-adds it in a few lines.

Ruling: R6 — T10 parses stored addresses with `netip.ParseAddr` and returns the error, not `netip.MustParseAddr`. Why: `build()` runs on whatever is in the settings row; a row written before the validator existed, or edited in the database directly, would panic the whole server at start rather than reporting a bad setting. Cost if wrong: none — strictly safer, same happy path.

## Progress

Task 1: implemented (commit bb0e951) — poller SetSource, nil-source tolerance, guarded reads.
Task 1: review — SPEC ✅ (9/9, no extra scope). QUALITY approved, 1 Important (plan-mandated), 2 Minor.
  Important: no test runs SetSource concurrently with Run, so the -race evidence never exercises
  the concurrency this task exists to enable. Reviewer confirmed lock correctness by inspection
  (cfgMu and mu are never held simultaneously; only two .src references, both guarded).
Task 1: minor (deferred): none carried — both minors folded into fix round 1 (see R7).

Ruling: R7 — the plan-mandated Important is fixed, not accepted. Why: the plan supplied three tests
verbatim and none is concurrent, but Task 10 calls SetSource from the settings-apply goroutine while
Run polls in its own — that is the entire purpose of this task, and `TestPollerSetInterval` already
establishes the `go p.Run(ctx)` pattern for the sibling API, so the fix is ~15 lines against an
existing template. Cost if wrong: one extra test that duplicates coverage the race detector would
have caught anyway. Bundling the stale struct doc comment (poller.go:15-17, still describes the
source as always present) into the same round, since the implementer is already in the file.

## Verified helper names (the plan guessed; these are real — carry into dispatches)

- internal/store tests: store helper is `open(t)`, NOT `openTestStore(t)`.
- internal/store migration coverage already exists: `TestOpenMigratesAnOlderDatabase` (store_test.go:216)
  builds a legacy schema, opens, and asserts the row survives with new fields at zero values;
  `TestMigrationsAreIdempotent` covers reopen. Task 2 Step 8 should extend these, not add a third.
- internal/adminapi: JSON helper is `writeJSON(w, status, v)` (api.go:340). There is NO `writeError`;
  the error helper is `writeErr(w, status, code, field, msg)` (api.go:314), plus `writeSettingsErr`
  (settings.go:123) and `writeRegistryErr` (api.go:324) for those two domains.
- internal/adminapi tests: harness is `newAPI(t) (http.Handler, string)` (api_test.go:16), NOT
  `newTestAPI`. `newAPIWithProviders(t)` (discovery_test.go:17) is the one that wires lease/health
  providers — Task 11's lease-endpoint tests want that one.

Task 1: fix round 1/5 (2 addressed, 0 open — concurrent SetSource test; stale struct doc comment; commits bb0e951..f772632)
Task 1: complete (commits 7dc7027..f772632, review clean)

Task 2: implemented (commit ac86d78) — DHCP settings columns, dhcp_leases table, migration, read/write.
Ruling: R8 — ACCEPT the implementer's out-of-brief change to ApplySnapshot (internal/store/store.go:933-959).
Why: the plan's global constraint says DHCP settings never replicate, and the cv_settings_u trigger
alone does not deliver that. ApplySnapshot re-writes the whole settings row from a pulled snapshot,
and already carried explicit preservation for dhcp_lease_file / discovery_interval / log_queries /
log_client_ip with the comment "Enforced here rather than trusted to the caller". Verified in the
code. Without the dhcp_* columns in that list, a replica pulling ANY replicated settings change
(a TTL edit, say) would silently overwrite its own local DHCP configuration from the primary — the
constraint would have been false in practice. The implementer followed the existing pattern exactly.
This is a defect in my plan, not scope creep by the implementer. Cost if wrong: seven extra fields
preserved across snapshot application, which is the conservative direction.
Task 2: review — SPEC ✅ (11/11). QUALITY approved, 0 Critical, 0 Important, 2 Minor.
  Reviewer independently confirmed: no dhcp_* column in cv_settings_u WHEN clause, no cv_ trigger on
  dhcp_leases, migration DDL byte-for-byte identical to base schema, 24 columns/placeholders/args all
  aligned in putSettings, and all 11 node-local columns preserved in ApplySnapshot.
Task 2: minor (deferred): comment above dhcp_leases (store.go:145) refers forward to tables ~80 lines below.
Task 2: minor (deferred): dhcp_leases sits before the cv_ block in the base schema, after the ALTERs in the migration (harmless ordering difference).
Task 2: complete (commits f772632..ac86d78, review clean)
Task 3: implemented (commit ce6fd7c) — dhcplease.go CRUD, delete-then-upsert across both unique keys.
Task 3: review — SPEC ✅ (5/5). QUALITY approved, 0 findings at any severity.
Task 3: complete (commits ac86d78..ce6fd7c, review clean)

Ruling: R9 — Task 4's `SuggestRange` drops its `host` and `gw` parameters; the signature becomes
`SuggestRange(subnet netip.Prefix) (start, end netip.Addr, err error)`. Why: the plan passes both and
uses neither, then suggests silencing the linter with `_ = host` — which is doubly wrong, since Go
does not complain about unused function parameters at all, and shipping two dead parameters is the
YAGNI defect the review rubric exists to catch. They are not needed: the allocator already excludes
the host's own address and the gateway from allocation via `Config.Host`/`Config.Gateway`
(Task 5 `usable()`), so the suggestion does not have to. Part 2's `dhcpSuggest` call site becomes
`dhcpd.SuggestRange(info.Subnet)`. Cost if wrong: one call site and one signature to widen later.
Task 4: implemented (commit 606f8b1) — internal/dhcpd/iface.go: Inspect, Qualifies, veth gate, parseProcRoute, SuggestRange.
Ruling: R10 — ACCEPT the implementer's correction to my own test fixture. The plan's
TestParseDefaultGateway used hex 0100A8C0 and claimed it decodes to 192.168.1.1; it decodes to
192.168.0.1. Independently verified: int.from_bytes(bytes.fromhex('0100A8C0'),'little') = 192.168.0.1,
and 192.168.1.1 is 0101A8C0. They fixed the INPUT and kept the intended expectation, rather than
weakening the assertion to match a wrong fixture — the right direction. Cost if wrong: none, arithmetic.
Task 4: review — SPEC ✅ (11/11). QUALITY approved, 0 Critical, 0 Important, 2 Minor observations.
  Reviewer hand-verified the little-endian conversion, both SuggestRange cases, the whole-line veth
  match, and ran a standalone program to confirm HasGlobalIPv6 excludes ULA/link-local/multicast.
Task 4: minor (deferred): Qualifies checks veth before the IPv4 check (order differs from the constraint prose; arguably more actionable).
Task 4: minor (deferred): Inspect takes the first IPv4 in OS-reported order; "first" has no semantic meaning on multi-address interfaces.
Task 4: complete (commits ce6fd7c..606f8b1, review clean)
Task 5: implemented (commit 8891492) — allocator: 4 priority rules, quarantine, exhaustion, NameTaken. Reconfigure correctly omitted (R5).
Task 5: review — SPEC ✅ except one rule partially met. QUALITY approved, 1 Important (plan-mandated), 1 Minor.
  Reviewer hand-traced index consistency across all four move combinations, loop termination at
  255.255.255.255, and the full locking discipline. No Critical found.

Ruling: R11 — FIX the reservation/protected-address gap in Task 5, do not defer it to Part 2.
Finding: `Allocate` case 1 (`if ip, ok := a.reserved[mac]; ok { return commit(ip) }`) never consults
`usable()`, so a reservation naming the server's own address or the gateway is handed to a client,
contradicting both the brief's stated rule and Config's own doc comment. Why fix here: the allocator
is the ONLY component that knows Host and Gateway — Part 2's `Reservations()` resolver is given just
the subnet, and the registry validating a service address knows neither. Deferring would park the
invariant where the facts to enforce it do not exist. Shape: split a `protected(ip)` predicate out of
`usable()` (host or gateway, range-independent, since reservations outside the range are legal), gate
case 1 on it, and fall through to normal allocation so a bad reservation costs the client nothing.
Cost if wrong: a deliberate reservation onto the gateway address stops working — which is not a
configuration anyone can want.
Bundling the reviewer's Minor with it: no test drives a MAC that already holds a dynamic lease onto a
different address, which is the highest-risk index-consistency path and is currently correct only by
hand-trace.

Ruling: R12 — Task 10 must NOT simply delete the `poller == nil` guards. My preflight table wrongly
recorded T1→T10 as OK. Those guards are not asking "does the poller object exist"; they stand in for
"is a lease source configured", and the UI depends on the distinction:
  - internal/app/serve.go:244-249 `leaseFn` returns nil when poller == nil
  - internal/app/serve.go:313-318 sets web Options.Leases to a nil FUNC in that case
  - internal/web/discovered.go:21 and :64 read `s.o.Leases == nil` as the off signal and render
    "DHCP lease discovery is not enabled" plus `"Enabled": s.o.Leases != nil`
Task 10 makes the poller always non-nil, so a naive simplification leaves Leases always non-nil, the
Discovered page reports discovery as Enabled forever, and the explanatory empty state becomes an
empty table. Worse, that flag is computed once at construction (the field is set from an IIFE), so it
cannot represent a source that is now switched on and off at runtime — which is the whole point of
Task 1.
Decision: Task 10 adds `DiscoveryOn func() bool` to web.Options and the adminapi equivalent, sets it
from serve.go to a live predicate over the runner's current source, and rewrites discovered.go's
three call sites to consult it. `Leases` becomes unconditionally non-nil. Existing discovered tests
must be updated to set the new field. Cost if wrong: one extra option field threaded through two
packages; the alternative is a UI that lies about whether discovery is running.
- internal/settings tests: base-value helper is `valid()` (validate_test.go:19), NOT `validSettings()`.
  Task 9's `dhcpSettings()` helper must build on `valid()`.
- internal/web Options carries `Leases func() []dhcp.Lease`; discovered.go treats a nil func as
  "discovery off" (see R12).

Ruling: R13 — Task 11's API surface changes. My plan invented `GET /api/dhcp/leases` on an `/api/`
prefix; neither is right.
  (a) Every route in this codebase is `/api/v1/...` (internal/adminapi/api.go:191-222). Use that.
  (b) A lease listing ALREADY EXISTS: `GET /api/v1/leases` → `listLeases` (api.go:222, :800), fed by
      the unexported `a.leases` field, returning `{"leases":[{hostname,address,mac,expires}]}` with
      expires as a Unix int. It already returns an empty list rather than erroring when no provider
      is wired.
Decision: do NOT add a parallel DHCP-only lease endpoint. Built-in DHCP leases reach `a.leases`
through the same poller the lease-file source uses, so `GET /api/v1/leases` already serves them
correctly the moment Task 10 wires the source. Task 11 instead adds `GET /api/v1/dhcp/status` for
what the existing endpoint cannot express — running, and why not — and leaves the lease list alone.
The plan's field names (`ip`, RFC3339 `expires`) are dropped in favour of the existing endpoint's
`address` and Unix `expires`; a second lease shape would be gratuitous drift.
Cost if wrong: the DHCP tab reads two endpoints instead of one, which it was going to do anyway.
Task 5: fix round 1/5 (2 addressed, 0 open — protected() gate on the reservation path; index-consistency tests both directions; commits 8891492..4fd5e19)
Task 5: complete (commits 606f8b1..4fd5e19, review clean)

Ruling: R14 — Task 6 drops the ICMP echo entirely. The probe becomes: send one throwaway UDP
datagram to the candidate address to force the kernel to ARP for it, wait within the 100ms budget,
then read /proc/net/arp and treat a COMPLETE entry (flag 0x2) as "in use".
Why: the plan calls `net.DialTimeout("ip4:icmp", ...)`, which needs CAP_NET_RAW. The spec grants the
service CAP_NET_BIND_SERVICE and nothing else, precisely so no raw sockets are needed — so in the
deployment we actually ship, that branch always fails and silently degrades to reading a cache. And
reading the ARP cache alone is nearly useless: it only holds addresses the host has talked to
recently, which is not the addresses we are about to hand out. The UDP poke is unprivileged, is one
mechanism rather than two, and turns a passive cache read into a real question — the kernel's
INCOMPLETE (0x0) vs COMPLETE (0x2) distinction that `parseARPTable` already parses IS the answer.
Cost if wrong: a probe that is weaker than an ICMP sweep on networks that firewall the poke port;
the DHCPDECLINE path is the backstop either way, and a false negative costs one declined address.
Task 6: implemented (commit 093575b) — UDP-nudge + ARP-table probe, no raw sockets.
Task 6: review — SPEC ✅ (10 met, 1 partial). QUALITY approved, 0 Critical, 0 Important, 4 Minor.
Task 6: minor (deferred): budget is ~100.5ms not 100ms — the /proc/net/arp read happens after the deadline is spent. Bounded (pseudo-file), but structural, on every call.
Task 6: minor (deferred): no test exercises parseARPTable's short/malformed-line guard; correct by inspection only.
Task 6: minor (deferred): `c.Write` return values discarded implicitly rather than `_, _ =`.
Task 6: process note — the reviewer could not corroborate my instruction to drop TestNopProberNeverBlocks's
  timing assertion, because it lived only in the dispatch prompt, not the ledger. Correct catch. Material
  dispatch corrections belong in the ledger; carrying that forward.
Task 6: complete (commits 4fd5e19..093575b, review clean)

## Task 7 dependency: API pre-verified by the controller (do not re-derive)

`go get github.com/insomniacslk/dhcp@latest` resolves to v0.0.0-20260728151720-c308df0fdcef.
I fetched it in a scratch module at /tmp/dhcpapi and read the real godoc. Every name the plan uses
exists with the signature the plan assumes:
  dhcpv4: NewReplyFromRequest(*DHCPv4, ...Modifier) (*DHCPv4, error); New(...Modifier);
    NewDiscovery(net.HardwareAddr, ...Modifier); FromBytes([]byte)
  Modifiers: WithMessageType(MessageType), WithYourIP(net.IP), WithServerIP(net.IP), WithOption(Option)
  Options: OptSubnetMask(net.IPMask), OptIPAddressLeaseTime(time.Duration), OptServerIdentifier(net.IP),
    OptRouter(...net.IP), OptDNS(...net.IP), OptDomainName(string), OptHostName(string),
    OptMessageType(MessageType), OptRequestedIPAddress(net.IP)
  Accessors: MessageType(), HostName(), RequestedIPAddress(), ServerIdentifier(), Router(), DNS(),
    DomainName(), IPAddressLeaseTime(def time.Duration), UpdateOption(Option), ToBytes()
  server4: NewServer(ifname string, addr *net.UDPAddr, handler Handler, opt ...ServerOpt) (*Server, error);
    (*Server).Serve() error; (*Server).Close() error; type Handler func(net.PacketConn, net.Addr, *dhcpv4.DHCPv4)
Note: the library ALSO offers direct modifiers WithNetmask/WithRouter/WithDNS/WithLeaseTime. The plan's
WithOption(Opt...) form is equally valid; either is fine, but pick one and be consistent.

Task 7: implemented (commit e59d9bb) — packet path, dhcp dep pinned v0.0.0-20260728151720-c308df0fdcef.
Task 7: review — SPEC ❌. QUALITY not approved: 1 Critical (plan-mandated), 1 Important, 1 Minor, 1 note.
  Reviewer independently confirmed sanitizeHostname is a true whitelist, that replies always broadcast
  and `peer` is genuinely discarded, and empirically confirmed SO_BINDTODEVICE works under a
  CAP_NET_BIND_SERVICE-only capability set (so the no-raw-sockets design holds).

Ruling: R15 — FIX the Critical. `Server.allocate`'s `commit` flag gates only the probe; it is never
threaded into `Allocator.Allocate`, whose commit closure unconditionally writes byMAC/byIP with a FULL
lease term. So a bare DISCOVER that is never followed by a REQUEST (a) burns a pool address for hours
and (b) publishes an attacker-chosen option-12 hostname into DNS. The reviewer demonstrated both with
a scratch test. The REQUEST/ACK trust boundary the design leans on does not exist — the code and its
own comment ("commit is false for an OFFER, which does not persist and does not claim a name") are
byte-identical to my plan at part1 lines 2285-2287, so this is my defect.
Fix: give the allocator an explicit lease duration per call, and have the OFFER path use a short hold
(60s) with an EMPTY hostname, while ACK uses cfg.LeaseTime with the real hostname. That is what real
DHCP servers do — an OFFER is a tentative hold, not a lease — and it closes both holes at once: a
name is only claimed once a client commits, and an un-followed-up DISCOVER frees its address in a
minute instead of a day. Cost if wrong: two clients could briefly be offered the same address under a
>60s DISCOVER→REQUEST gap; DHCP tolerates that by design, and the ACK path re-checks.

Ruling: R16 — FIX the Important. Start's two goroutines both assume the caller cancels the context,
but Task 10 passes context.Background(). So the `<-ctx.Done()` watcher never exits (one leaked
goroutine per DHCP reconfigure) and the `ctx.Err() == nil` guard never fires, meaning every
deliberate Stop logs Error("dhcp server stopped") indistinguishable from a crash. Fix: Start derives
its own cancellable context from the caller's and stores the cancel func; Stop calls it BEFORE
Close(), so the watcher exits and ctx.Err() is non-nil by the time Serve returns its read error.
Cost if wrong: none — strictly fewer goroutines and quieter logs.

Ruling: R17 — also fix the reviewer's Note now rather than leaving it for Part 2. `normalizeMAC` only
lowercases and trims. It is safe today because its only input is `m.ClientHWAddr.String()`, already
canonical — but Part 2 compares reservations against it, and my own Part 2 self-review already flagged
that the agreement between `registry.NormalizeMAC` and `dhcpd.normalizeMAC` is guarded by nothing but
a comment. Making this one parse via net.ParseMAC and re-render costs three lines and removes the
hazard before anything depends on it. Cost if wrong: none.

## Amendments Part 2's committed plan now needs (docs/superpowers/plans/2026-08-19-kydns-builtin-dhcp-part2.md)

Rulings taken during Part 1 have invalidated parts of the Part 2 document. It must be revised before
it is executed, or its implementers will write code against signatures that no longer exist:

1. R9 — Part 2 Task 4's `dhcpSuggest` calls `dhcpd.SuggestRange(info.Subnet, info.Addr, info.Gateway)`.
   The signature is now `SuggestRange(subnet netip.Prefix)`. One call site.
2. R15 — Part 2 must not assume `Allocate(mac, hostname, requested)`. Task 7's fix adds an explicit
   lease duration. Part 2 does not call Allocate directly today (it only calls SetReservations), so
   this is a read-through check rather than a known break — verify when revising.
3. R13 — Part 2 Task 4 adds `GET /api/dhcp/status` and `/api/dhcp/suggest`. Routes in this codebase
   are `/api/v1/...`. Both become `/api/v1/dhcp/...`. Its `writeError` helper does not exist either;
   the real one is `writeErr(w, status, code, field, msg)`.
4. R13 — Part 2 Task 4's test helper `newTestAPI` does not exist; it is `newAPI(t)` / `newAPIWithProviders(t)`.
5. R12 — Part 2 Task 5's web tab must read discovery state from the `DiscoveryOn func() bool` option
   Task 10 introduces, not from `Leases != nil`.
6. R17 — Part 2 Task 2's `registry.NormalizeMAC` and `dhcpd.normalizeMAC` now BOTH parse via
   net.ParseMAC, so the "guarded only by a comment" hazard named in Part 2's self-review is closed.
   That paragraph should be rewritten rather than left claiming a weakness that no longer exists.

Ruling: R2a — amends R2 with the concrete ordering, because R2 as written is impossible. Verified in
serve.go: `live := &liveComponents{...}` is built at :195, but `promotedAt` is read at :203, `role`
computed at :208, and `roleHolder := NewRoleHolder(role)` only exists at :213. So a `dhcpRunner` that
needs the role cannot be passed into the liveComponents literal where R2 said to put it, and assigning
`live.dhcp` later would leave the literal holding a nil pointer.
Fix: move the three-statement promotion/role block (`promotedAt, err := st.Promotion()`, the
`RoleAtBoot` call, its log line, and `NewRoleHolder`) to just ABOVE the `live := &liveComponents{...}`
construction. It depends on nothing but `st`, `cfg`, and `logger`, all of which exist far earlier, and
nothing between :195 and :213 depends on it. Then construct `dhcpRun` after `roleHolder` and pass it
into the literal normally. Cost if wrong: a compile error, caught in the same task.
