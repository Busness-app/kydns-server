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

Task 7: fix round 1/5 (4 addressed, 1 NEW Critical open — the OFFER path's empty hostname and 60s
  hold now overwrite a lease the client already holds; commits e59d9bb..0c091d7)
  Re-reviewer proved all four original findings closed empirically (bare DISCOVER publishes no name,
  reaches neither Leases() nor the store; hold is exactly offerHold; ACK still commits the real name
  and cfg.LeaseTime; INFORM never allocates; all 32 Allocate call sites carry the ttl). Then proved
  the regression with two failing tests.

Ruling: R18 — FIX the regression the R15 fix introduced. A tentative hold must never weaken a lease
the client already holds. Finding: `Allocator.Allocate`'s `commit` closure (alloc.go:105) writes
`Hostname: hostname, Expires: now.Add(ttl)` unconditionally, and rule 2 (`alloc.go:117`) routes an
already-held MAC into it. Post-R15 the OFFER path passes `hostname=""` and `ttl=offerHold`, so a bare
DISCOVER for a MAC that already holds a full named lease rewrites it to no name and 60 seconds.
Verified in the code by me, and demonstrated by the re-reviewer: the victim's A record disappears from
`Server.Leases()` immediately, and 60s later the victim's address is ACKed to a different client while
still in use. Remotely triggerable by one unauthenticated broadcast packet carrying the victim's MAC;
also fires with no attacker whenever a client DISCOVERs and does not REQUEST. Contradicts the spec's
"first claim wins FOR THE LIFE OF THAT LEASE" — a DISCOVER is not a lease operation and must not cut
a lease's life.
Shape (binding invariant; the shape is a recommendation): split the tentative path out as
`Allocator.Offer(mac string, requested netip.Addr, hold time.Duration)` delegating to a private
`allocate(..., tentative bool)`, and inside `commit`, when `tentative` and the client already holds
this same IP, keep the previous hostname and never move `Expires` earlier. Gating rule 2 alone is NOT
sufficient: rule 1 (reservation) reaches `commit` for a reserved client that already holds its
address, and would strip the name the same way. Keeping the guard out of the ACK path preserves the
spec's "a device that sends no hostname gets no name" on REQUEST.
Cost if wrong: an operator who shortens dhcp.lease_seconds sees outstanding leases keep their old
longer term until they lapse — which is what a client already believes it holds anyway.

Task 7: minor (deferred): a second `Start` without an intervening `Stop` overwrites `s.cancel`,
  leaking the first context (server.go:114-117). Same class as the pre-existing `s.srv` overwrite.
  Carry into Task 10: `dhcpRunner.Reconcile` must `Stop` before it `Start`s.
Task 7: minor (deferred): `TestAckGrantsTheFullLeaseTerm` (server_test.go:727) would have passed
  pre-fix — the ACK path always used cfg.LeaseTime. It is a regression guard, not evidence.

Task 7: fix round 2/5 (R18 addressed as prescribed — private `allocate(..., tentative bool)`,
  unchanged `Allocate`, new `Offer`, guard inside `commit` so rules 1 and 2 are both covered; commit
  0c091d7..b5e773d). RED-first: the three regression tests were shown failing against the unmodified
  code before the fix. I read the alloc.go diff myself; it is the prescribed shape, plus one
  tightening I accept — the guard requires `prev.Expires.After(now)`, so a tentative hold cannot
  resurrect a dead lease's name into Leases() for 60s.

Ruling: R19 — the conflict probe is not gated on "new to us", and that defeats R18 in production.
Reported by the round-2 implementer as a concern; I verified it in the code before ruling.
Finding: `Server.allocate`'s OFFER branch (server.go:266-277) calls `s.opts.Prober.InUse(l.IP)` for
EVERY offer, and on a hit does `Quarantine(l.IP)` + `Alloc.Release(mac)`. The address it probes on a
renewal is the one the client is currently using, so the client's own ARP answer quarantines its
address for 10 minutes and releases the very lease R18 exists to protect. R18's new tests only hold
because they run under `nopProber`. This is not hypothetical: a client that DISCOVERs while still
holding its address is routine (NetworkManager or dhclient restarted, wifi re-association, a VM
resumed), and each one loses its DNS name and burns a pool address.
This also reverses an earlier ledger call. The preflight recorded this as "comment, not behaviour —
deferred minor", judging the comment to be the defect. That was wrong: the spec's "Conflict probing"
section says the probe runs "before offering an address that is new to us — NOT a renewal, not a
reservation". The comment states the spec correctly; the code violates it.
Decision: fix in Task 7, round 3. The server cannot tell a renewal from a fresh pick — only the
allocator knows which rule fired — so `Offer` reports it: `Offer(mac, requested, hold) (l Lease,
fresh, ok bool)`, where `fresh` is true only when the address came from rule 3 (requested-and-free) or
rule 4 (lowest free). Rules 1 and 2 return `fresh == false` and the server skips the probe. That is
the spec's own wording ("new to us") expressed once, in the only place that knows.
Why not the smaller fix the implementer proposed (compare the offered address against the one the MAC
already holds): it misses rule 1. A reserved client that already holds its reserved address would
still be probed, its own answer would quarantine the reservation for 10 minutes, and it would fall
through to a dynamic address — a Part 2 break shipped from Part 1.
Cost if wrong: an address genuinely stolen by a static-IP squatter, which a client then renews onto,
is never re-probed until that lease lapses. DHCPDECLINE remains the backstop.

Task 7: deferred to Part 2: `allocate` rule 1 commits a reservation with no freeness check, so a bare
  DISCOVER from a reserved MAC evicts whatever OTHER MAC currently holds that IP (the R18 guard keys
  on the same MAC, so it does not cover this). Unreachable in Part 1 — `SetReservations` is only ever
  given an empty map — but it lands the moment Part 2 wires reservations. Added to the Part 2
  amendments list below as item 7.
Task 7: fix round 2 re-review — R18 ADDRESSED, no new breakage. The re-reviewer reproduced the
  pre-fix RED independently (git archive of 5608247 into /tmp with the new test files copied over,
  repo untouched) and mutation-tested the guard with three mutants: leaking the hostname into the
  OFFER, using LeaseTime instead of offerHold, and letting the guard leak onto the ACK path — each
  mutant is caught by a distinct test. The guard does not over-apply.
Task 7: fix round 2 re-review — R19 CONFIRMED with a reproduction. Counting prober: ACK is never
  probed, every OFFER is, renewal and reservation alike. With a stub prober reporting the client's own
  address in use, a bare DISCOVER from the holder takes Leases() from one named 24h lease to empty,
  quarantines the client's real address for 10 minutes, and moves it to a fresh unnamed 60s hold —
  net effect identical to the Critical R18 fixed. Reservation variant is worse: Quarantine does not
  gate rule 1, so the retry re-commits the same address it just quarantined, losing only the name and
  the term. All three R18 tests flip PASS→FAIL when nopProber is swapped for that stub.

Task 7: deferred to Part 2: the R18 guard requires `prev.IP == ip`, so it does not fire when a
  tentative hold lands on a DIFFERENT address than the one held. Two shapes, both verified by the
  re-reviewer, neither reachable in Part 1: (a) a reservation added for an address the client does not
  currently hold — a bare DISCOVER moves it and drops the name (needs Part 2's SetReservations);
  (b) a restored lease whose address falls outside a narrowed range, so rule 2's `usable` check skips
  it (needs an operator range change plus a restart). R18's ruling scoped the guard to the same
  address deliberately; widening it is Part 2's call.
Task 7: fix round 3/5 (R19 addressed, 0 open Critical/Important; commits b5e773d..f68d07b).
  `Offer` now returns `(Lease, fresh, ok)` with fresh true only for rules 3 and 4; the server probes
  on `fresh && InUse`. Re-reviewer reproduced the pre-fix harm in an exported copy of b5e773d (both
  the renewal and the reservation variant), then mutation-tested seven mutants — fresh forced true,
  fresh forced false, each of the four rules mislabelled, and the round-2 tentative guard deleted.
  None survived. Confirmed no test opens a socket and that the de-blinded round-2 test gained
  discriminating power without losing any.

Ruling: R20 — fold the two Minors from the round-3 re-review into a round 4 rather than deferring
them to the whole-branch review. Normally minors never enter the loop; these two are the exception.
  (a) `alloc.go:134` — rule 2 has no expiry check, so a MAC whose lease lapsed is still reported
      `fresh == false` and its address is never probed. `byMAC` is pruned only by `restore()` at boot
      (there is no reaper; `DeleteExpiredDHCPLeases` has one non-test caller), so on a long-running
      server a departed client's entry persists indefinitely and a static device that has since taken
      that address is handed it again unprobed. This is a coverage regression that round 3 itself
      introduced — at b5e773d the address WAS probed — and it makes the code diverge from the spec's
      own words: an expired holding is "new to us" again. The re-reviewer supplied and verified the
      whole fix: `return commit(l.IP, !l.Expires.After(now))`.
  (b) No server-path test covers rule 3 (a DISCOVER carrying option 50 for a free address the prober
      reports in use). Both repo probe tests drive a bare DISCOVER, so they exercise rule 4 only.
      Mutant (c) — rule 3 mislabelled not-fresh — was caught by the allocator unit test alone and by
      nothing at the packet layer.
Why not defer: one expression with a verified patch already in hand, plus one test. A final review
would only hand it back. Cost if wrong: one extra round on a converging loop.
Model note: round 4 goes to a cheaper model, not the escalation the skill prescribes for rounds 4-5.
That rule exists for loops that are not converging; this one has closed its finding every round, and
the remaining work is one expression whose exact text is already known.

Task 7: minor (deferred): `TestDiscoverDoesNotProbeAReservedClientsAddress` (server_test.go:668)
  asserts "not quarantined" by reading the unexported `Alloc.quarantine` map. Accurate and race-free,
  but avoidable — the re-reviewer demonstrated a behavioural equivalent (drop the reservation,
  Release, re-request the address). Nit, not a defect.
Task 7: fix round 4/5 (2 addressed, 0 open; commits f68d07b..c069aa7). Re-reviewer independently
  reproduced Finding A's RED in an exported copy of f68d07b, and independently mutated rule 3 to
  confirm Finding B's new test discriminates. Traced the hazard I flagged — round 2's tentative guard
  and round 4's fresh flag read the same `byMAC[mac]` with the same `now` at the same boundary, so
  there is no mismatch window: live lease -> guard applies and unprobed; expired -> guard skipped and
  probed.
Task 7: complete (commits 093575b..c069aa7, review clean after 4 fix rounds)

Ruling: R21 — Task 8's probe socket must bind to the configured interface. The plan's
`DetectForeign(ctx, iface, wait, self)` accepts `iface` and never uses it: it calls
`net.ListenPacket("udp4", ":68")` and broadcasts from an unbound socket, which leaves on the default
route's interface. That is not the R9 case of a merely dead parameter — here the parameter is
semantically required. The spec's "Rogue-server detection" says the DISCOVER goes out "on the
configured interface", and a multi-homed host is exactly the case that matters, since the whole
feature is about choosing one interface out of several. An unbound probe would test the wrong segment,
come back clear, and let us bind a second DHCP server onto a segment that already has one — the single
failure this feature exists to prevent.
Fix: build the socket with `net.ListenConfig{Control: ...}` setting SO_BINDTODEVICE to `iface`, and
SO_REUSEADDR while there (cheap insurance against a host DHCP client that binds :68; standard
practice for DHCP clients). `golang.org/x/sys` is already in the module graph (go.mod:98, indirect),
so this promotes an existing dependency rather than adding one. Task 7 established that
SO_BINDTODEVICE works under a CAP_NET_BIND_SERVICE-only capability set — that was confirmed
empirically by the task 7 reviewer — so this needs no new capability. Note there is no in-repo
helper to copy: task 7 gets SO_BINDTODEVICE from `server4.NewServer(ifname, ...)` inside the library.
Cost if wrong: on a single-homed host the bind is a no-op, so the downside is a few lines and one
promoted dependency.

Ruling: R22 — a probe that could not run is not a clear. `DetectForeign` returning an error means we
do not know whether another server is present; treating that as "no rogue found" silently deletes the
protection on exactly the hosts where it is hardest to run (a host whose own DHCP client holds :68).
Task 10 must refuse to start the listener on a probe error and report the reason, the same as a
positive detection, with the spec's existing override as the operator's escape hatch. Fail-closed is
what the spec's own decision table asks for — "Refuses to enable when another server answers: the one
failure that ruins an evening" — and two DHCP servers on one segment is worse than DHCP not starting
with a message saying why. Task 8's obligation is only that the error be distinguishable and name the
cause; the decision itself is Task 10's. Cost if wrong: an operator on a host running its own DHCP
client must tick the override to enable DHCP, having been told exactly why.

Task 8: implemented (commit 381af25) — rogue.go: DetectForeign, collectForeign, probeMAC,
  bindToDevice. R21 and R22 both honoured; the reviewer confirmed SO_BINDTODEVICE needs no capability
  by running a standalone program as an unprivileged uid on this host, and confirmed a bogus device
  name surfaces as an error rather than silently binding unbound.
Task 8: review — SPEC ❌. QUALITY not approved: 1 Critical, 2 Important, 6 Minor.

Ruling: R23 — FIX the Critical: the probe DISCOVER must set the broadcast flag. `dhcpv4.NewDiscovery`
leaves `Flags == 0`, and RFC 2131 §4.1 says that with BROADCAST clear and giaddr/ciaddr zero the
server UNICASTS its OFFER to yiaddr and chaddr. Our probe is a SOCK_DGRAM socket using a random MAC
that belongs to no NIC on the host, so that frame is filtered in hardware and the datagram is
addressed to an IP we do not own: the OFFER is structurally unreceivable. ISC dhcpd and dnsmasq both
behave this way. So on the exact network the feature is built for — one that already has a DHCP
server — the probe would come back clear and Task 10 would start a second listener. A probe that
converts "unknown" into a false "safe" is worse than no probe at all.
Fix: `dhcpv4.NewDiscovery(mac, dhcpv4.WithBroadcast(true))`. Verified `WithBroadcast(bool) Modifier`
exists in the pinned v0.0.0-20260728151720-c308df0fdcef. This is the same reasoning the spec already
records for our own replies under "Sockets" — a client that cannot receive a unicast to an address it
does not have must ask for broadcast, or you need CAP_NET_RAW. Setting the flag keeps us on one
capability. Cost if wrong: none; a broadcast OFFER is receivable by every client either way.

Ruling: R24 — FIX the Important: split the receive loop out so it is testable. The brief fixed
`DetectForeign`'s signature such that it builds its own socket, which put the deadline arithmetic, the
unparseable-packet skip, and the reply filter on the untestable side of the line — and that is where
the Critical lived. The spec's own Testing table asks for "a fake responder on a loopback conn", which
the chosen signature forecloses, and the global constraint already says every packet test runs against
a fake `net.PacketConn`. Extract `readReplies(conn net.PacketConn, xid dhcpv4.TransactionID)` and also
`newProbeDiscovery(mac)` so a test can assert the broadcast flag directly — otherwise R23 is a
one-line fix with nothing stopping it from being reverted. Cost if wrong: two more unexported
functions in one file.

Ruling: R25 — FIX the Important: correlate replies by transaction ID, not by chaddr. `FromBytes`
truncates `ClientHWAddr` to the wire's `hlen`, so a server that returns `hlen = 0` or pads chaddr
produces a string that will not match ours and its genuine OFFER is silently dropped — another false
clear, the same failure direction as R23. RFC 2131 requires the server to echo `xid`, and we already
hold it. Verified `TransactionID` is a field on `dhcpv4.DHCPv4` in the pinned version. Cost if wrong:
a reply that spoofs our xid is counted; it is still a foreign DHCP server answering on our segment.

Ruling: R26 — FIX the Minor about a missing option 54: fall back to the datagram's source address for
`ServerID` when the OFFER carries no server identifier, rather than discarding the reply. An OFFER
answering our probe is proof of a foreign server whether or not it is conformant, and every branch
that drops a reply fails toward a false clear, which is the catastrophic direction. Three lines. Our
own server cannot be reported by this path: its source address is our own address, which the existing
`id == self` check already excludes. Cost if wrong: an operator sees a rogue named by its source IP
rather than by its server identifier.
Task 8: fix round 1/5 (7 addressed, 0 open; commits 381af25..3fb20a3). Re-reviewer proved the
  broadcast flag at the wire (ToBytes bytes 10-11 = 0x8000, round-trips through FromBytes) rather than
  at the constructor, confirmed NewDiscovery's modifier order cannot reset it, and killed five mutants:
  WithBroadcast removed, WithBroadcast(false), xid filter removed, xid filter inverted, option-54
  fallback reverted. It also re-verified the four original collectForeign tests each still kill their
  own mutant, and confirmed empirically that readReplies' reused 1500-byte buffer cannot corrupt an
  earlier reply because FromBytes copies every field it keeps.
  Noted on the RED evidence: it was produced against an intermediate that never existed as a commit
  (extraction applied, decisions pre-fix), so it is weaker as provenance than it reads. The mutation
  results are the stronger evidence and they hold.
Task 8: minor (deferred): the deadline arithmetic (rogue.go:54-57) and `probeMAC` (rogue.go:155-162)
  are pure logic that stayed on the untestable side of the R24 split; nothing asserts the
  locally-administered/unicast bit twiddle.
Task 8: minor (deferred): `TestNewProbeDiscoveryAsksForABroadcastReply` asserts `m.IsBroadcast()`, a
  struct-field read, rather than the serialized byte. The wire property holds — the re-reviewer
  verified it — but the shipped assertion is one level removed from what matters.
Task 8: minor (deferred): a server answering twice, once with option 54 and once without, is counted
  as two Foreign entries (the fallback key differs from the option-54 key). Over-reports, which is the
  safe direction.
Task 8: minor (deferred): an OFFER carrying an explicit 0.0.0.0 in option 54 parses as a valid Addr,
  so it never reaches the source-address fallback and is reported as a server at 0.0.0.0.
Task 8: minor (deferred): the readReplies loop ends only on the socket deadline, not on ctx
  cancellation. Bounded at 2s.
Task 8: complete (commits c069aa7..3fb20a3, review clean)

Task 9: R4 applies — the brief still carries the same-/24 rule verbatim, so it is overridden at
dispatch: pool size capped at 65536, `end >= start` kept, no subnet-shape rule. Also dropping the
brief's "end in another subnet" rejection case: under R4 a range spanning two /24s is legal by design
(SuggestRange produces one on a /22), and that case only passes today because 10.0.0.5 happens to be
numerically below 192.168.1.128, which the "end below start" case already covers. Replaced with a
size-cap case and its inclusive boundary. Helper names verified in the package before dispatch:
`valid()` (validate_test.go:19), `bad(field, format, args...)` and `FieldError` (validate.go:19, :26);
`netip` and `strings` are already imported by validate.go.

Ruling: R27 — nothing validates that the range lies inside the interface's subnet, and after R4
nothing checks its shape either. The spec's Settings table says range_start/range_end "must be inside
the interface's subnet", but `validateDHCP` deliberately never reads host state — correctly, since the
stored value must validate the same way on every node. That leaves the check homeless: a range outside
the interface's subnet would have the allocator hand out addresses no client on that segment can use.
Decision: Task 10's `build()` owns it. It already reads the interface via `Inspect`, so it is the only
place that holds both facts, and a failure there is reportable through the same path as a rogue
detection or a bad address — refuse to start and name the reason. Carry into Task 10's dispatch.
Cost if wrong: an operator who mistypes a range gets a clear refusal at start instead of a DHCP server
that hands out unusable addresses.

Task 9: implemented (commit bec310f) — validateDHCP, parseIPv4, R4's pool cap, R27's comment.
Task 9: review — SPEC ❌. QUALITY not approved: 1 Critical, 0 Important, 2 Minor.
  Reviewer confirmed R4's same-/24 block was not written, R27's comment names the subnet-containment
  omission and points at Task 10, the disabled gate covers the lease-file mutual exclusion too,
  `end.Less(start)` runs before the subtraction so it cannot underflow, `be32` is big-endian, the
  65536 boundary is inclusive, and the tests assert FieldError.Field via errors.As.
  Critical: `size := be32(end) - be32(start) + 1` is uint32 arithmetic, so start 0.0.0.0 / end
  255.255.255.255 wraps size to 0, `0 > 65536` is false, and the entire IPv4 space is accepted as a
  DHCP range — defeating the exact mechanism R4 added the cap for. Reviewer reproduced it by running
  the expression directly.
Task 9: minor (deferred): `parseIPv4` trims before parsing but quotes the untrimmed input in the
  error. Not a functional bug — a value that only needed trimming would have parsed.
Task 9: fix round 1/5 (2 addressed, 0 open; commits bec310f..a5982be). Re-reviewer independently
  reproduced the RED at bec310f (archived it, dropped in the new test file, watched the whole-space
  subtest fail) and computed every boundary fixture rather than eyeballing it: 10.0.0.0->10.1.0.0 is
  65537, 0.0.0.0->255.255.255.255 is 2^32, and the pre-existing 10.0.0.0->10.0.255.255 acceptance case
  is exactly 65536 and still passes, so the cap did not shift. Both operands are widened before the
  subtraction, not after.
Task 9: complete (commits 3fb20a3..a5982be, review clean)

## Task 10 pre-dispatch verification (controller; do not re-derive)

Every name Task 10's brief uses, checked in the tree at a5982be:
- Roles: `RolePrimary` / `RoleReplica` / `RoleStandalone` (role.go:15-19). Accessor is
  `roleHolder.Current()` (used at serve.go:237, :257, :260); `.Role()` does not exist.
- `dhcpd.New(o Options) *Server` (server.go:63) — returns no error.
- `dhcpd.Qualifies(name string) error` (iface.go:77); `dhcpd.Inspect(name) (IfaceInfo, error)` (iface.go:37).
- `dhcpd.NewAllocator(cfg Config, now func() time.Time) *Allocator` (alloc.go:49).
- `dhcpd.NewProber(iface string, budget time.Duration) Prober` (probe.go:44).
- `dhcpd.DetectForeign(ctx, iface string, wait time.Duration, self netip.Addr) ([]Foreign, error)` (rogue.go:34).
- `discovery.NewPoller(src dhcp.Source, interval time.Duration, onChange func(), logger *slog.Logger) *Poller` (poller.go:33).
- The four `poller == nil` sites: serve.go:244-249 (`leaseFn`), :313-318 (the IIFE feeding
  web Options.Leases), :337 (`go poller.Run`), plus the construction at :146.
- R12's UI sites: `web.Options.Leases` (middleware.go:47, with the doc comment that nil means off);
  `discovered.go:21`, `:64` (`"Enabled": s.o.Leases != nil`), `:77`.
- adminapi: field `leases` (api.go:30), `WithProviders(leases, statuses)` (api.go:71), `listLeases`
  nil-check (api.go:802), `promoteLease` nil-check returning "lease discovery is not enabled"
  (api.go:817). `WithProviders` has exactly two call sites: serve.go:266 and
  adminapi/discovery_test.go:29. `srv.o.Leases` is set at six places in web/discovered_test.go
  (:16, :46, :62, :72, :95). Small enough to update honestly — no compatibility shim.

Ruling: R28 — Task 10's packaging step is already done. `packaging/kydns.service` ALREADY carries
`AmbientCapabilities=CAP_NET_BIND_SERVICE` and `CapabilityBoundingSet=CAP_NET_BIND_SERVICE` for port
53. The brief's Step 7 would add a duplicate directive. The only change wanted is the comment above
them, which currently claims "Port 53 is the only privileged thing KyDNS does". Also checked the rest
of the unit against what Parts 1 needs: `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX` covers our
sockets, `SystemCallFilter=@system-service` covers setsockopt, and neither `ProtectKernelTunables` nor
`PrivateDevices` blocks the prober's `/proc/net/arp` read. Cost if wrong: a stale comment.

Task 10: implemented (commit 4c1ee3a) — dhcpRunner, serve/apply wiring, R12's DiscoveryOn across web
  and adminapi, packaging comment.
Task 10: review — SPEC ❌. QUALITY not approved: 0 Critical, 3 Important, 4 Minor.
  All seven overrides landed correctly and the reviewer verified each: R1 `!= RoleReplica` with a
  RoleStandalone case, R2a's moved block checked for side-effect drift (nothing between the old and
  new positions references role/roleHolder, nothing logs there), R6's parseSetting, R22 failing
  closed, R12 with no shim, R27's containment check, R28 comment-only.
  It also independently cleared three things I had flagged as risks: `dhcpConfigEqual` covers every
  field `build()` reads (diffed line by line); the server->poller->server reentrancy cannot deadlock
  (`OnChange` is called with `s.mu` released and `Leases` takes no lock); lock order is
  `d.mu -> RoleHolder.mu` and `d.mu -> poller.cfgMu` with no reverse edge. And the both-set
  DHCPEnabled+DHCPLeaseFile row cannot reach Serve: `ensureSettings` runs `ValidateStored` on the
  loaded row, so it refuses to boot.

Ruling: R29 — FIX the doc move. The spec's "Applying without a restart" makes it a requirement of
this task, in the two files it names. `README.md:153` still tells operators `dhcp_lease_file` cannot
change in a running process and that a banner will name the running and saved values; this commit
made both statements false. `docs/superpowers/specs/2026-08-13-kydns-settings-in-the-ui-design.md:45`
still lists it under "Requires a restart, and says so", and `:186` still describes the banner. The
docs are the part of this change an operator actually reads. Cost if wrong: none — the code is the
authority and the docs are catching up to it.

Ruling: R30 — FIX the promotion gap. The spec says "A replica never starts the listener, whatever its
local dhcp.enabled says. Promotion starts it." Reviewer confirmed by reading `replication.go:243-260`
that `Promote` records, stops the pull loop, sets the role, and returns — and that `Reconcile` has
exactly two non-test callers, `serve.go:229` (boot) and `apply.go:78` (settings save). So a promoted
node serves DNS at once but leaves DHCP down until someone saves settings or restarts. That is the
worst possible moment for it: promotion happens when the primary has failed, which is exactly when
the LAN has no DHCP server. The runner was built for this — `role` is read at every Reconcile rather
than captured once, which is the expensive half of the design — and then nothing pulls the trigger.
Shape: `replicaPromoter` gains `onPromote func()`, set in serve.go to reconcile from the current
settings snapshot, called after `p.role.Set(RolePrimary)`. `Promote` already returns early unless the
node is actually a replica, so it fires once per real transition, and both `Promote` and `Reconcile`
are idempotent. Out-of-brief-scope is not a reason to ship a node that does not do what the spec's
promotion clause says. Cost if wrong: a promoted node starts DHCP a few milliseconds after it starts
accepting writes, which is the intended order anyway.

Ruling: R31 — FIX the orphaned lease-file source. `apply.go:83` gates the lease-file swap on the
requested setting (`if !s.Raw.DHCPEnabled`) rather than on what is actually running. Reviewer's
scenario, which I accept: a node discovering from a dnsmasq lease file; the operator saves
`dhcp.enabled=true` with `dhcp_lease_file` cleared (the validator forces clearing it in the same
save); `build()` refuses because dnsmasq is still answering. `Reconcile` returns with nothing running
and never touches the source — `stopLocked` returns early when nothing is running — and the
`!DHCPEnabled` branch is skipped. The poller keeps polling a path the settings row no longer contains,
those leases keep entering the zone, and the Discovered page reports discovery on. Fix: gate on
whether the built-in listener is actually running (`l.dhcp.Status()`), not on the requested setting,
so the source always ends up matching the row. Cost if wrong: on a failed enable the node stops
publishing lease-file names it was told to stop publishing, which is what the operator asked for.

Task 10: minor (deferred to the whole-branch review): `dhcp.go:62` — `stopLocked()` runs before
  `build()`, so a save the validator accepts but `build()` rejects (an out-of-subnet range, a renamed
  interface, a foreign server that appeared since) takes a working listener down. Building first
  would make a rejected configuration a no-op, but it is not free: `DetectForeign` would then run with
  our own listener bound, and `collectForeign` only filters replies whose server identifier equals
  `info.Addr` — so a reconfigure onto a DIFFERENT interface would detect our own server as a rogue and
  refuse. That trap needs Task 8-level care, and the ordering was plan-mandated, so it goes to the
  final review to triage rather than into this fix round.
Task 10: minor (deferred): the off-state copy on the Discovered page still names only
  `dhcp_lease_file` as the way to turn discovery on. Part 2 UI work.
Task 10: fix round 1/5 (5 addressed, 0 open; commits 4c1ee3a..3c3d51e). Re-reviewer confirmed the
  promotion hook is wired end to end at the only non-production-test construction site
  (serve.go:297-301), that every promotion path funnels through adminapi/replicas.go:84 so the hook
  covers all of them, and that it reconciles from a live snapshot rather than a captured one. Mutation
  results: onPromote call deleted -> caught; onPromote moved BEFORE role.Set -> caught (the ordering
  is pinned, not just the call); apply.go gate reverted -> caught; promoteLease's discoveryEnabled
  check deleted -> caught by the new test only, which is exactly the gap Finding 5 named. No mutant
  survived. Traced all four DHCPEnabled x DHCPLeaseFile combinations; the source matches the settings
  row in each.
  Accepted the one out-of-brief change: `internal/web/templates/settings.html:103` carried the same
  now-false "restart required" claim on the page that saves the key.
Task 10: minor (deferred): `kydns.example.yaml:139-140` still says changing `dhcp_lease_file` takes a
  restart and that the Settings screen will ask you to restart. Same false claim R29 fixed elsewhere,
  in a shipped operator-facing artifact. Folding into Task 11's dispatch.
Task 10: minor (deferred to the whole-branch review): the settings design doc heads `private_domain`
  with "Requires a restart, and says so" (:47-51) while :193 now says nothing produces that banner.
  The DHCP spec ordered `private_domain` left in place, and the round-1 implementer separately
  reported that `Apply` renames the zone live — so the "requires a restart" claim may itself be stale.
  That is a question about a pre-existing setting, not about DHCP; it needs a ruling, not a fix here.
Task 10: complete (commits a5982be..3c3d51e, review clean)

## Task 11 pre-dispatch verification (controller; do not re-derive)

- Routes are `/api/v1/...` behind an `auth(...)` wrapper (api.go:224-241). `GET /api/v1/leases` ->
  `listLeases` and `POST /api/v1/leases/{ip}/promote` already exist.
- Test helpers: `newAPI(t)` (api_test.go:16), `newAPIWithProviders(t)` (discovery_test.go:17),
  `newAPIWithDiscovery(t, on)` (discovery_test.go:24), `newReplicaAPI(t, status)` (replica_test.go:15).
  Neither `newTestAPI` nor `newTestReplicaAPI` exists.
- Providers are attached by builder methods, not exported fields: `WithMetrics`, `WithProviders`,
  `WithPolicy`, `WithSettings`, `WithReplication` (api.go:61-110). `WithReplication` takes a plain
  func, which is the precedent for a status provider.
- CLI: `Commands` (cli.go:100-110) is the single registry — the comment records that a command
  implemented but not listed there was unreachable from the binary, twice. Settings syntax is
  `kydns settings set <key>=<value>`; keys are snake_case mirroring the DTO json tags
  (`settingsKinds`, settings.go:27-35) and `settingsUsage` (settings.go:12-22) lists them. Test helper
  is `clientFor(srv)`. There is no lease-listing command today.

Ruling: R32 — the settings DTO fields need yaml tags as well as json tags. The brief supplies only
`json:"..."`. `internal/adminapi/settings.go:11-16` documents why that is a bug: "yaml tags mirror the
json ones: import decodes with yaml.Unmarshal (JSON is a YAML subset), and a field with no yaml tag
falls back to its lowercased Go name instead of its snake_case json name, which would silently blank
every field on import." So DHCP settings would survive a save but be wiped by any settings import.
Every neighbouring field carries both tags. Cost if wrong: none — it matches the file's own rule.
Related, decided rather than deferred: the DHCP fields DO belong in the export/import document.
`dhcp_lease_file` is equally node-local and is already exported with a yaml tag, so excluding the new
fields would be the inconsistency. Export/import is a deliberate operator action, not the replication
path the node-local constraint is about — that path is the `cv_settings_u` trigger and
`ApplySnapshot`, both of which already exclude these columns (R8).

Ruling: R33 — the CLI keys are `dhcp_enabled`, `dhcp_interface`, `dhcp_range_start`, `dhcp_range_end`,
`dhcp_gateway`, `dhcp_lease_seconds`, `dhcp_secondary_dns`. The brief guesses dotted names
("if other keys are dotted (`health.interval`)") and they are not: `settingsKinds` is keyed by the
DTO's json tags and its comment says so. The brief's example test is wrong twice over — the syntax is
`settings set <key>=<value>`, not `settings set <key> <value>`. Cost if wrong: a CLI key that does not
match the wire field, rejected by `settingsSet`'s own unknown-key check.

Ruling: R34 — the CLI gets one new command, `dhcp`, with `status` and `leases`, registered in
`Commands`. The spec's "Operator surface" says the CLI gets "the same settings and a read-only lease
listing", and there is no lease command today. `leases` reads the existing `GET /api/v1/leases` (R13:
built-in leases reach it through the same poller, so no DHCP-only lease endpoint is added) and, when
the list is empty, consults status so an operator who enabled DHCP and sees nothing is told why rather
than shown a blank. Not a top-level `leases` command: keeping it under `dhcp` costs one registry entry
instead of two and matches the existing `service add|list|rm` shape. Cost if wrong: a rename.

Ruling: R35 — the runner reaches the API as `WithDHCP(status func() (bool, error))`, not the brief's
exported `API.DHCP interface{ Status() (bool, error) }` field. Every other provider on this type is
attached by a `With*` builder and the struct's fields are unexported; `WithReplication(status func()
ReplicaStatus)` is the exact precedent for a status provider passed as a func. `dhcpRunner.Status` is
already `func() (bool, error)`, so serve.go passes the method value directly. Cost if wrong: one
signature.

Task 11: implemented (commit 64616a0) — DTO fields both directions with both tag sets,
  GET /api/v1/dhcp/status, WithDHCP builder, serve wiring, CLI keys + usage, the `dhcp` command and
  its registry entry, kydns.example.yaml comment.
  Process note: the implementing agent was interrupted before reporting or committing, and its session
  was lost. A second agent verified the uncommitted tree, wrote the report marked explicitly as a
  third-party verification with no RED-first evidence available, and committed. I told the reviewer the
  provenance was weak and asked it to check discriminating power against the base rather than assume a
  red-green history. It did: five of the six load-bearing tests provably fail at 3c3d51e.
Task 11: review — SPEC ✅. QUALITY approved, 0 Critical, 0 Important, 6 Minor.
  Reviewer confirmed the node-local constraint by tracing that replication pulls via
  `store.SnapshotInput`, not the `settingsDTO` this task edited, so the new yaml tags cannot leak DHCP
  settings to a peer — `settingsDTO` reaches yaml only through export/import, which are deliberate
  operator commands. It also independently verified the out-of-brief `postServerSettings` fix against
  the handler: it builds a fresh `store.Settings{}` and full-replaces, `store.Settings` already carried
  the seven DHCP fields at the base commit, and the form has no DHCP inputs — so at base every save
  from /settings/server zeroed all seven and switched off a running DHCP server. Genuine Critical-class
  defect, correctly fixed here, and `patchSettings` never had it because it decodes onto
  `toSettingsDTO(cur)`.
Task 11: minor (deferred): two back-to-back `s.liveSettings()` calls in `postServerSettings`
  (:118, :126) could be one read, closing a narrow window where the two blocks see different snapshots.
Task 11: minor (deferred): the DHCP carry in `postServerSettings` is a read-modify-write outside
  `Settings.Set`'s writeMu, so a concurrent API PATCH between the read and the Set is silently lost.
  Pre-existing shape of the whole handler — `private_domain` has the same window — so the DHCP fix
  does not make it worse. A proper fix is a compare-and-swap in `Settings.Set`.
Task 11: minor (deferred): `kydns dhcp leases` consults status only when the list is empty, so with
  lease-file discovery on and the built-in server off it prints a full table and never says the
  built-in server is not running.
Task 11: minor (deferred): `Reconcile` clears `lastError` on the not-wanted branch (dhcp.go:54), so a
  replica with dhcp_enabled=true reports "running no" with no reason and `kydns dhcp status` has
  nothing to show. Task 10 owns the cause; Task 11 is the surface that makes it visible.
Task 11: minor (deferred): `TestDHCPSettingsRejectedOnAReplica` passes at the base commit unchanged —
  the write gate rejects any settings PATCH on a replica regardless of body. Harmless guard, but not
  coverage of this task.
Task 11: minor (deferred): with built-in DHCP on, setting `dhcp_lease_file` from /settings/server now
  fails validation naming a field that page does not render. The message renders as readable plain
  text and refusing beats the base behaviour of silently switching DHCP off; Part 2's DHCP tab removes
  the dead end.
Task 11: complete (commits 3c3d51e..64616a0, review clean)

## All 11 tasks complete. Whole-branch review next.

## Whole-branch review (7dc7027..64616a0, 22 commits)

Reviewed in seven passes on the most capable model. Verdict: ready to merge WITH FIXES.
2 Critical, 5 Important, 12 Minor. Findings written to final-findings.md for the fix wave.
The reviewer checked all 36 rulings and could not show any of them mistaken. It qualified two:
  - R22's stated justification leans on "the spec's existing override as the operator's escape hatch",
    and that override is Part 2. As shipped, a host whose own DHCP client holds :68 without SO_REUSEADDR
    can never enable built-in DHCP and has no way to say "I know, do it anyway". Acceptable only because
    the feature is off by default — so Part 2's override is a prerequisite for advertising the feature,
    not a nice-to-have.
  - R32 is correct that export/import should carry the DHCP fields and that this is not the replication
    path, but importing node A's document onto node B is now the one supported operation that can plant
    one node's DHCP configuration on another, with the rogue probe as the only guard. Given C2 that
    guard has a hole. Worth a sentence in the export docs.
It also named two defects in the SPEC rather than the implementation: the Replication section promises
unknown clients "will be NAKed", which the design never specified anywhere else (finding I5), and the
Security notes say malformed packets are "counted" but no counter was ever specified (no metric exists).

Two Criticals survived precisely because every task was reviewed against its own diff:
  - C1 lives in the DECLINE branch that R15/R18/R19/R20 never revisited. One spoofed broadcast packet
    destroys any client's lease and quarantines any address, demonstrated. Same harm R18 rated Critical,
    reached by a packet type nobody looked at. Plus an attacker-fed unbounded quarantine map, which
    contradicts the spec's "the lease table is bounded by the range size by construction".
  - C2 lives in the interaction between a self-filter written for Part 2's periodic probe and a bind
    whose SO_REUSEADDR behaviour nobody measured. The reviewer measured it: server4 sets SO_REUSEADDR
    and SO_REUSEPORT, so a second bind onto :67 SUCCEEDS alongside a dnsmasq-style socket, and broadcast
    DISCOVERs are delivered to both. So the co-resident case is invisible to the probe AND unstopped by
    the bind — on the deployment this feature most directly competes with.
That is the process lesson worth keeping: per-task review cannot see a seam between two tasks, and both
Criticals lived in exactly such a seam.

Deferred-minor triage from the final review: 18 ship as-is, 1 already resolved, 2 fix before merge
(the stopLocked-before-build ordering I had deferred, now folded into the C2 fix; and the trim
divergence), 4 cheap and worth it, 2 correctly deferred to Part 2 but must block it (the reservation
freeness check and the R18 guard's `prev.IP == ip` limit — both unreachable in Part 1 only because
SetReservations is always given an empty map, and both land the instant Part 2 wires reservations;
they belong at the top of Part 2's plan, not its backlog), 2 carried forward.

Fix wave 1 (commits 64616a0..cc8ac96): C2, I1-I5 and all nine small items ADDRESSED and each pinned by
a mutant the re-reviewer ran. C1 only half addressed — see R36. Two deviations from the prescription
were both judged right calls: removing `self` from DetectForeign/collectForeign entirely rather than
passing a zero Addr (there is no address-based filter Part 2 could reuse anyway — dnsmasq co-resident
and our own listener both put OUR address in option 54, and readReplies already correlates on the probe
xid, which our own server also answers; Part 2 must gate on "our listener is bound" regardless), and
`Decline` returning a bool so the persisted row and OnChange only move when a lease actually moved.
I5's leaked hold was investigated and cleared: after a NAKed REQUEST the allocator holds the address for
a lease term, but the client's re-DISCOVER is offered that same address and converges in one DORA
round-trip, and five repeated NAKed REQUESTs from one MAC consume exactly one address — N addresses
still cost N distinct MACs, the same as a plain REQUEST flood cost before. No amplification.

Ruling: R36 — fix C1's residual now rather than parking it, and accept that this is a second fix wave
where the skill allows only one. The skill's rule exists to stop unbounded fix cycles; it also says to
rule on load-bearing residuals rather than park them, and this is as load-bearing as a finding gets.
Finding: `alloc.go:180` guards with `a.byIP[ip] != mac`. For a free address `a.byIP[ip]` is `""`, and
`normalizeMAC` returns `""` for a packet with `hlen = 0` (`net.HardwareAddr(nil).String()`), so an
anonymous DECLINE satisfies the guard. The re-reviewer proved it end to end through the real parse path
— `server4.Serve` does no chaddr validation — and swept the pool with 11 packets: "a legitimate client
got 0 replies after the sweep". Every free address quarantined for ten minutes, from any host on the
segment, with no MAC, repeatable forever. Existing leaseholders keep renewing, so the harm is precisely
"no new or expired client can get an address" — which on a home LAN is indistinguishable from the outage
this whole feature exists to prevent. Each packet also drives a `DeleteDHCPLease("")` and a synchronous
zone rebuild, unrated.
Also fixing, same root cause: the RELEASE branch has no equivalent guard, so an `hlen = 0` RELEASE flood
drives one delete plus one synchronous rebuild per unauthenticated packet. The reviewer named it
out-of-scope; it is the same hole through a different door and it would be indefensible to ship the
DECLINE fix without it.
Also: mutant B survived — `TestDeclineOutsideTheRangeIsNotQuarantined` declines from a MAC that holds
nothing, so it returns at the MAC check and never evaluates `inRange`. The range guard is live in
production (`Load()` restores out-of-range rows after a narrowed range, and rule 1 commits reservations
in or out of the range), so it needs a test that actually reaches it.
Cost if wrong: three one-line guards and two tests, in code the next reviewer reads anyway.

Fix wave 1: new Minor found — `app/dhcp.go:64`, `fail()` leaves `d.current` naming the running listener
(correctly, so it keeps naming the live interface), but that makes re-saving the working configuration
after a refused save hit the `dhcpConfigEqual` early return and never clear `lastError`. `kydns dhcp
status` then prints `running yes` with a stale `last error` until the next real config change. Pre-fix
it cleared itself. Folding into R36's round.
Fix wave 1: minor (deferred): `app/dhcp.go:143-196` still uses dotted names in its prose errors while
the validator now uses wire names, so an operator sees two spellings of the same setting. Cosmetic —
these are not FieldError.Field values, so nothing breaks.

## Additional Part 2 amendments from the completion run (items 7-13)

Consolidated here because they are otherwise scattered across 550 lines of ledger. Items 1-6 are in
the section above, from the earlier session.

7. **`dhcpd.Allocate` and `dhcpd.Offer` changed shape.** `Allocate(mac, hostname, requested, ttl)`
   gained an explicit lease duration (R15), and `Offer(mac, requested, hold) (Lease, fresh, ok)` is a
   new entry point for the OFFER path (R18, R19). Part 2 calls neither today — only `SetReservations` —
   so this is a read-through check, but verify before writing against the old two-value shape.
8. **`DetectForeign` and `collectForeign` no longer take `self`.** The whole-branch review proved the
   address-based self-filter could not work: dnsmasq co-resident and our own listener both put OUR
   address in option 54, so filtering on it made a second DHCP server on the same host invisible —
   while `server4`'s `SO_REUSEADDR`/`SO_REUSEPORT` meant the `:67` bind did not refuse either. Part 2's
   periodic probe must re-add suppression of our own answer, and it must gate on "our listener is
   currently bound", not on an address. Note `readReplies` already correlates on the probe xid, which
   our own server also answers, so xid is not a filter either.
9. **Reservations land on two known holes, both currently unreachable and both blocking for Part 2.**
   (a) allocation rule 1 commits a reservation with no freeness check, so a bare DISCOVER from a
   reserved MAC evicts whatever OTHER MAC holds that IP; the R18 tentative guard keys on the same MAC
   and does not cover it. (b) the R18 guard requires `prev.IP == ip`, so it does not fire when a
   tentative hold lands on a DIFFERENT address than the one held — which is exactly what adding a
   reservation for an address the client does not currently hold does. Both are unreachable in Part 1
   only because `SetReservations` is always given an empty map. They belong at the top of Part 2's
   plan, not in its backlog.
10. **The rogue-server override is now a prerequisite, not a nice-to-have.** R22 makes a probe that
    could not run refuse to start, and Part 1 has no override key — so a host whose own DHCP client
    holds `:68` without `SO_REUSEADDR` cannot enable built-in DHCP at all and has no way to say "I know,
    do it anyway". That is only acceptable because the feature is off by default. Part 2's override
    must cover the probe-error case as well as the foreign-server-found case.
11. **Export/import can now plant one node's DHCP configuration on another.** R32 put the seven
    `dhcp_*` fields in the export document, correctly and consistently with `dhcp_lease_file`. The
    consequence: importing node A's document onto node B is the one supported operation that copies
    node-local DHCP settings across nodes, with the rogue probe as the only thing between that and two
    servers on a segment. Worth a sentence in the export docs.
12. **Two defects are in the SPEC, not the implementation.** The Replication section promises that
    clients whose leases a promoted replica does not know "will be NAKed and re-DISCOVER" — behaviour
    the design never specified anywhere else, and which had to be built during the fix wave. And the
    Security notes say malformed packets are "counted and dropped"; they are dropped, but no counter
    was ever specified and none exists. Decide whether to add the metric or amend the spec.
13. **`private_domain`'s restart status is unresolved.** The settings design doc heads it "Requires a
    restart, and says so", but `Apply` renames the zone live (`TestApplyRenamesTheZoneEverywhere`) and
    the restart-pending banner now has no producer at all. The DHCP spec said to leave `private_domain`
    where it is, so Part 1 did — but the heading looks simply false. Needs a ruling from the operator,
    not a silent fix.

Fix wave 2 (commits cc8ac96..cbd6646): all four findings ADDRESSED, no new breakage. The re-reviewer
rebuilt the tests against the base commit and reproduced the exact RED for each — the anonymous DECLINE
sweep quarantining three addresses, the anonymous RELEASE driving one store delete and one zone
rebuild, `Decline` accepting a client that named no MAC, and the stale probe error surviving a
recovered save. All three mutants killed, each producing exactly one failing test: the `mac == ""`
rejection, the unconditional quarantine (which is the direct proof that finding 3's corrected test now
reaches `inRange`), and the central `handle()` guard. It also checked the guard does not drop a message
type we serve: all five named-MAC message tests still pass, and it round-tripped a named DISCOVER with
`GatewayIPAddr` set through ToBytes/FromBytes to confirm a relay changes giaddr and does not zero
chaddr on the wire.

Controller note: while finishing, my shell's working directory had reset to the main checkout and one
bookkeeping command ran against `main` instead of this worktree. It failed cleanly — the paths do not
exist there — and nothing was written or committed to main. Recorded because it is the exact
wrong-tree hazard this worktree exists to prevent, and the next run should use absolute paths.

## Branch complete. 24 commits, 19 packages green, vet and gofmt clean.
