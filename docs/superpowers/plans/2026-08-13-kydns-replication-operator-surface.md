# Linked-Server Replication: Operator Surface Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make replication usable by an operator — replicas refuse writes, peers pair from the CLI, replicas can be promoted, and both roles are legible in the web UI.

**Architecture:** A single `Role` value (primary / replica / standalone) is derived once at startup and published to the admin API, the web UI, and the CLI. A default-deny middleware refuses mutating requests on a replica, with two named exemptions. Pairing gets its first real caller. Health replicates as operational metadata outside the config version.

**Tech Stack:** Go 1.26.5, `modernc.org/sqlite`, `crypto/tls`, `crypto/ed25519`, `net/http` with Go 1.22 method-pattern routing. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-08-13-kydns-linked-server-replication-design.md`

**Predecessor:** `docs/superpowers/plans/2026-08-13-kydns-replication-core.md` (part 1, merged at `b8fb826`). Part 1 built identity, pairing, the pinned TLS transport, snapshot pull, and config wiring. It shipped with no operator surface at all.

## Global Constraints

- Module path `github.com/yoshiofthewire/kydns-server`. Go 1.26.5.
- Tests run with `CGO_ENABLED=0 go test ./...` (`make test`). Build with `make build`. `go vet ./...` and `gofmt -l .` must be clean.
- All SQL lives in `internal/store`. No SQL elsewhere.
- Write tests FIRST and see them FAIL before implementing. Where the red is only a compile error, mutate the finished implementation to prove the test catches the regression, capture the output, and revert. Part 1 did this throughout and it repeatedly caught weak tests.
- No `time.Sleep` in tests.
- Short comments explaining why. No prose blocks defending the code. Do not use the words "note that".
- Roles: `primary` (accepts writes, serves snapshots), `replica` (read-only, pulls), `standalone` (neither key set). Decided from config, never inferred.
- Staleness threshold and poll backoff ceiling are both 60s. Poll interval is 5s.

## The exemption that makes this work

A replica refuses writes. But two writes must still be possible on a replica, or it can never stop being one:

- **promote** — the operator's deliberate action to make this node a primary.
- **join** — pairing, which writes `replica_state`.

So the write gate is default-deny with exactly those two exemptions, the same shape Ruling 6 in part 1 settled for the replication listener. A route added later without thought must be refused, not allowed. Getting this backwards means either a replica nobody can promote during an outage — the exact moment promotion exists for — or a replica that silently accepts writes it will overwrite on the next pull.

## Carried forward from part 1

Fix these as part of the task that touches the same code, not as a separate cleanup pass:

| Item | Where | Task |
|---|---|---|
| `serve.go` holds the `*Puller` as `_`; `Status()` has no caller | `internal/app/serve.go` | 1 |
| `PutPeer` upserts, so a re-pair resets an operator's `Label` and zeroes `last_sync_at`/`last_version` | `internal/store/peer.go` | 5 |
| `reachable()` fires before the NodeID check, so a wrong-key peer holds the loop at 5s instead of backing off | `internal/replica/puller.go` | 4 |
| No assertion that pairing's two dials still carry `requestTimeout` | `internal/replica/pairing_exchange_test.go` | 6 |

---

### Task 1: Role plumbing and live status

**Files:**
- Create: `internal/app/role.go`
- Modify: `internal/app/serve.go`, `internal/app/replication.go`, `internal/adminapi/api.go`
- Test: `internal/app/role_test.go`, `internal/adminapi/replica_test.go`

**Interfaces:**
- Consumes: `config.ReplicationConfig`, `replica.Puller`, `replica.Status`.
- Produces:

```go
// Role is what this node is, decided from configuration at startup.
type Role string

const (
	RolePrimary    Role = "primary"
	RoleReplica    Role = "replica"
	RoleStandalone Role = "standalone"
)

func RoleFrom(cfg config.ReplicationConfig) Role

// ReplicaStatus is what the API and UI render. Nil Puller means this node
// is not a replica.
type ReplicaStatus struct {
	Role          Role   `json:"role"`
	PrimaryAddr   string `json:"primary_address,omitempty"`
	PrimaryNodeID string `json:"primary_node_id,omitempty"`
	NodeID        string `json:"node_id,omitempty"`
	LastSyncUnix  int64  `json:"last_sync_unix,omitempty"`
	LastVersion   int64  `json:"last_version,omitempty"`
	LastError     string `json:"last_error,omitempty"`
	Stale         bool   `json:"stale,omitempty"`
}
```

Part 1 left `_ = puller` in `serve.go`. Retain it and expose `Status()` through
a `GET /api/v1/replica/status` endpoint. Without this task nothing else in the
plan can render anything.

- [ ] **Step 1: Write the failing tests**

`internal/app/role_test.go`:

```go
func TestRoleFromConfig(t *testing.T) {
	cases := []struct {
		name string
		cfg  config.ReplicationConfig
		want Role
	}{
		{"standalone", config.ReplicationConfig{}, RoleStandalone},
		{"primary", config.ReplicationConfig{Listen: ":8443"}, RolePrimary},
		{"replica", config.ReplicationConfig{Primary: "10.0.0.2:8443"}, RoleReplica},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := RoleFrom(tc.cfg); got != tc.want {
				t.Fatalf("RoleFrom(%+v) = %q, want %q", tc.cfg, got, tc.want)
			}
		})
	}
}
```

Both keys set is already a startup error in `config.validate`, so `RoleFrom`
never sees it and must not invent a fourth answer for it.

`internal/adminapi/replica_test.go` must assert:

- A standalone node reports `role: standalone` and no primary fields.
- A replica reports its primary's address, its last sync, and `stale` once the
  clock passes 60s since the last successful sync.
- The endpoint requires authentication like every other admin route.

- [ ] **Step 2: Run to verify failure**

```bash
CGO_ENABLED=0 go test ./internal/app/ ./internal/adminapi/ -run Role -v
```

Expected: FAIL — `undefined: RoleFrom`.

- [ ] **Step 3: Implement**

Create `internal/app/role.go`. In `serve.go`, keep the `*Puller` returned by
`startReplication` and hand it, plus the role, to `adminapi.New`. Add
`GET /api/v1/replica/status` to `internal/adminapi/api.go` behind `auth`.

The admin API must not import `internal/app` — pass a small interface or a
status-producing func into `adminapi.New` rather than the concrete type.

- [ ] **Step 4: Run the tests**

```bash
CGO_ENABLED=0 go test ./... 
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/app/ internal/adminapi/
git commit -m "feat(app,adminapi): publish the node's replication role and status

Part 1 computed a Puller and dropped it on the floor. Nothing could see
whether a replica was syncing, which is the first thing an operator asks."
```

---

### Task 2: The write gate on the admin API

**Files:**
- Modify: `internal/adminapi/api.go`
- Test: `internal/adminapi/writegate_test.go`

**Interfaces:**
- Consumes: `Role` from Task 1.
- Produces: a middleware wrapping the whole admin mux.

**Default-deny, as in part 1's Ruling 6.** Wrap the entire mux, not each
route. Refuse any request whose method is not GET or HEAD when the role is
replica, with `409 Conflict` and a body naming the primary's address. Exempt
exactly two paths: `POST /api/v1/replica/promote` and
`POST /api/v1/replica/join`.

- [ ] **Step 1: Write the failing tests**

The central test is a table over EVERY mutating route, derived from the mux
rather than hand-listed, so a route added later is covered automatically:

```go
// Every mutating admin route must be refused on a replica. The list is
// derived from the router, so a route added later fails this test rather
// than silently accepting writes a replica will overwrite on its next pull.
func TestEveryMutatingRouteIsRefusedOnAReplica(t *testing.T)
```

If the mux cannot be enumerated, hand-list the routes AND add a test that the
hand-list matches the registered routes, so the two cannot drift. Do not ship
a hand-list with nothing keeping it honest.

Also assert:

- The 409 body names the primary's address, so an operator knows where to go.
- `GET` and `HEAD` are unaffected on a replica.
- A primary and a standalone node accept writes normally.
- `POST /api/v1/replica/promote` is accepted on a replica — the exemption.
- `POST /api/v1/replica/join` is accepted on a replica — the exemption.
- A route added later without explicit treatment is refused. Register a
  throwaway `POST /api/v1/whatever` in the test and assert 409.

- [ ] **Step 2: Run to verify failure**

```bash
CGO_ENABLED=0 go test ./internal/adminapi/ -run Replica -v
```

Expected: FAIL — writes currently succeed on a replica.

- [ ] **Step 3: Implement**

One middleware in `internal/adminapi/api.go`, applied to the mux in `New`.

- [ ] **Step 4: Run the tests**

```bash
CGO_ENABLED=0 go test ./...
```

- [ ] **Step 5: Commit**

```bash
git add internal/adminapi/
git commit -m "feat(adminapi): refuse writes on a replica

Default-deny over the whole mux with two named exemptions, promote and
join, because a replica that cannot be promoted is useless in exactly the
outage promotion exists for."
```

---

### Task 3: The write gate in the web UI

**Files:**
- Modify: `internal/web/middleware.go`, `internal/web/render.go`, `internal/web/templates/*.html`
- Test: `internal/web/replica_test.go`

Two halves, and both are needed:

**Enforcement.** Every `requireCSRF` POST route is refused on a replica. Same
default-deny shape as Task 2 — wrap, do not enumerate.

**Presentation.** Edit controls render **disabled**, with the title or helper
text "Managed by *&lt;primary address&gt;*". Disabled, never hidden: a control
that vanishes reads as a bug, a disabled one explains itself. A standing
banner appears on every page when this node is a replica whose last sync is
older than 60s.

Read paths stay fully open — a replica's dashboard, stats, blacklist status
and logs are its own and live.

- [ ] **Step 1: Write the failing tests**

```go
func TestReplicaRefusesEveryPostRoute(t *testing.T)      // derived from the router
func TestReplicaRendersDisabledControlsNotHiddenOnes(t *testing.T)
func TestReplicaShowsStaleBannerPastSixtySeconds(t *testing.T)
func TestReplicaDashboardStillRenders(t *testing.T)       // reads are unaffected
func TestPrimaryRendersNormally(t *testing.T)
```

`TestReplicaRendersDisabledControlsNotHiddenOnes` must assert the control is
PRESENT and carries `disabled`, not merely that the page differs. Asserting
absence would pass against a template that hid it, which is the outcome this
test exists to prevent.

- [ ] **Step 2: Run to verify failure**

```bash
CGO_ENABLED=0 go test ./internal/web/ -run Replica -v
```

- [ ] **Step 3: Implement**

Follow the existing `banner.go` pattern for the standing banner rather than
inventing a second mechanism.

- [ ] **Step 4: Run the tests**

- [ ] **Step 5: Commit**

```bash
git add internal/web/
git commit -m "feat(web): a replica shows why it cannot be edited

Disabled with 'Managed by <primary>', never hidden -- a control that
vanishes reads as a bug, a disabled one explains itself."
```

---

### Task 4: Health status replication

**Files:**
- Modify: `internal/replica/server.go`, `internal/replica/transport.go`, `internal/replica/puller.go`, `internal/app/replication.go`
- Test: `internal/replica/health_test.go`

**Interfaces:**

```go
// On the primary, served outside the config version because health changes
// constantly and must not invalidate configuration.
// GET /replica/health-status -> {"statuses": {"<service>": "healthy"|"unhealthy"|"unknown", ...}}

func (c *Client) HealthStatus(ctx context.Context) (map[string]string, error)
```

The replica fetches health on the same poll tick as the version check, and
holds the result for its own UI.

**When the primary is unreachable, a replica reports health as `unknown` —
never the last known value.** An unreachable primary must not make a dead
service look alive. This is the one behaviour in this task that matters, and
it gets an explicit test.

Also fix the carried item: `reachable()` currently fires before the NodeID
check in `puller.go`, so a peer answering with the wrong key holds the loop at
the 5s interval instead of backing off. Move the transition so a rejected
reply counts as a failure.

- [ ] **Step 1: Write the failing tests**

```go
func TestHealthStatusReplicates(t *testing.T)
func TestUnreachablePrimaryReportsHealthUnknownNotStale(t *testing.T)
func TestHealthDoesNotAffectConfigVersion(t *testing.T)
func TestWrongKeyPeerBacksOff(t *testing.T)   // carried fix
```

- [ ] **Step 2: Run to verify failure**

- [ ] **Step 3: Implement**

Add the route on the primary's replication listener. It is a pinned route —
do NOT add it to `unpinnedPaths`.

- [ ] **Step 4: Run the tests**

- [ ] **Step 5: Commit**

```bash
git add internal/replica/ internal/app/
git commit -m "feat(replica): replicate health, and never fake it

An unreachable primary reports unknown rather than the last value it saw.
Stale health would make a dead service look alive."
```

---

### Task 5: Replica management API and CLI — primary side

**Files:**
- Modify: `internal/adminapi/api.go`, `internal/store/peer.go`, `internal/cli/cli.go`
- Create: `internal/adminapi/replicas.go`, `internal/cli/replica.go`
- Test: `internal/adminapi/replicas_test.go`, `internal/cli/replica_test.go`, `internal/store/peer_test.go`

**Endpoints** (primary only; a replica gets 409 from Task 2's gate):

| Route | Effect |
|---|---|
| `POST /api/v1/replicas/invite` | Mint a pairing code; returns the code, its expiry, and this node's fingerprint |
| `GET /api/v1/replicas` | List peers with last sync, version lag, status |
| `DELETE /api/v1/replicas/{node_id}` | Unpair |

**CLI:** `kydns replica invite`, `kydns replica list`, `kydns replica remove <node-id>`.

`invite` must print the code AND this primary's fingerprint together, because
the operator needs both in front of them to complete `join` on the other box.

**Carried fix:** `store.PutPeer` upserts and so resets an operator's `Label`
and zeroes `last_sync_at`/`last_version` on a re-pair. Add a targeted writer
that preserves those on re-pair, or split insert from update. `replica list`
showing a label that vanishes when a node re-pairs is a small thing that
makes the whole screen untrustworthy.

- [ ] **Step 1: Write the failing tests**

```go
func TestInviteReturnsCodeAndFingerprint(t *testing.T)
func TestInviteIsRefusedOnAReplica(t *testing.T)
func TestListReplicasReportsLagAndLastSync(t *testing.T)
func TestRemoveReplicaUnpins(t *testing.T)
func TestRePairPreservesOperatorLabel(t *testing.T)   // carried fix, store-level
```

- [ ] **Step 2: Run to verify failure**

- [ ] **Step 3: Implement**

Follow the CLI style already in `internal/cli/blacklist.go` — subcommand
dispatch, table output to stdout, errors to stderr.

- [ ] **Step 4: Run the tests**

- [ ] **Step 5: Commit**

```bash
git add internal/adminapi/ internal/cli/ internal/store/
git commit -m "feat(adminapi,cli): mint invites and manage replicas"
```

---

### Task 6: `kydns replica join` — the replica side

**Files:**
- Modify: `internal/cli/replica.go`, `internal/adminapi/replicas.go`
- Test: `internal/cli/join_test.go`

This is where `replica.PairAsReplica` finally gets a non-test caller. Part 1
shipped it unreachable.

```
kydns replica join <address> <code> [--fingerprint <fp>] [--yes]
```

**Interactive:** dial, show the fingerprint the peer presented, and ask the
operator to confirm it matches what the primary displays. Confirm, then the
code is sent.

**Scripted:** `--fingerprint` supplies the expected value and the comparison
happens without a prompt. A mismatch fails without sending the code.

**There is no prompt-free default that trusts whatever answered.** Absent both
a TTY and `--fingerprint`, the command fails with a message saying which to
supply. `--yes` alone must NOT skip the fingerprint check — it may only skip
an unrelated confirmation. Getting this wrong reopens exactly the
man-in-the-middle the SSH model closes, which is the whole reason this design
exists (see `docs/superpowers/specs/2026-08-13-kydns-pake-selection.md`).

- [ ] **Step 1: Write the failing tests**

```go
func TestJoinPromptsAndPairsOnConfirmation(t *testing.T)
func TestJoinWithMatchingFingerprintNeedsNoPrompt(t *testing.T)
func TestJoinWithMismatchedFingerprintSendsNoCode(t *testing.T)
func TestJoinWithoutTTYOrFingerprintRefuses(t *testing.T)
func TestYesFlagDoesNotSkipTheFingerprintCheck(t *testing.T)
func TestJoinReportsARejectedFingerprintDistinctly(t *testing.T)  // ErrFingerprintRejected
```

`TestJoinWithMismatchedFingerprintSendsNoCode` must assert against codes the
primary actually received, exactly as part 1's
`TestDeclinedFingerprintSendsNoCode` does — a recording handler and an empty
slice. Asserting only that the command failed would pass even if the code had
been sent and rejected.

**Carried fix:** add the assertion part 1's re-review flagged as missing —
that pairing's two dials each still carry `requestTimeout`.

- [ ] **Step 2: Run to verify failure**

- [ ] **Step 3: Implement**

- [ ] **Step 4: Run the tests**

- [ ] **Step 5: Commit**

```bash
git add internal/cli/ internal/adminapi/
git commit -m "feat(cli): join a primary by confirming its fingerprint

Pairing had no caller until now. There is no prompt-free default that
trusts whatever answered the connection."
```

---

### Task 7: Promotion and demotion

**Files:**
- Modify: `internal/adminapi/replicas.go`, `internal/cli/replica.go`, `internal/app/replication.go`, `internal/store/peer.go`
- Test: `internal/adminapi/promote_test.go`, `internal/cli/promote_test.go`

**Promotion** (`POST /api/v1/replica/promote`, `kydns replica promote`): the
node stops pulling, begins accepting writes, keeps its current configuration
as the new truth, and clears its stored primary.

The confirmation states plainly that the old primary must be demoted or
rebuilt before it returns. Two primaries serving the same replicas is the one
state this design cannot detect or reconcile, and nothing may create it
silently.

Promotion changes a file-owned key's effective meaning, so decide and document
how it survives a restart: either it rewrites `replication.primary` in the
config file, or it records the promotion in the database and the config key is
read only when no promotion is recorded. **Pick the database option** — KyDNS
does not rewrite an operator's config file anywhere else, and starting now
would be a surprise. Say so in a comment.

**Demotion** (`kydns replica join` on a former primary): re-pairs it as a
replica and its next poll replaces its local configuration wholesale. That is
destructive, so the CLI names what it will discard — service count, record
count, and the primary it will follow — and requires confirmation.

- [ ] **Step 1: Write the failing tests**

```go
func TestPromoteStopsPullingAndAcceptsWrites(t *testing.T)
func TestPromoteSurvivesRestart(t *testing.T)
func TestPromoteIsAllowedOnAReplica(t *testing.T)       // the Task 2 exemption
func TestPromoteOnAPrimaryIsANoOpNotAnError(t *testing.T)
func TestDemoteNamesWhatItWillDiscard(t *testing.T)
func TestDemoteRequiresConfirmation(t *testing.T)
```

- [ ] **Step 2: Run to verify failure**

- [ ] **Step 3: Implement**

- [ ] **Step 4: Run the tests**

- [ ] **Step 5: Commit**

```bash
git add internal/adminapi/ internal/cli/ internal/app/ internal/store/
git commit -m "feat(replica): promote a replica, demote a primary

Promotion is recorded in the database, not by rewriting the operator's
config file -- KyDNS does not edit that file anywhere else."
```

---

### Task 8: The web UI for replication

**Files:**
- Create: `internal/web/replication.go`, `internal/web/templates/replication.html`
- Modify: `internal/web/pages.go`, `internal/web/templates/dashboard.html`
- Test: `internal/web/replication_test.go`

**On a primary:** a Replicas screen listing each peer with its last successful
sync and version lag, an *Add replica* button that mints a code and displays
it beside this node's fingerprint, and a remove control per peer.

**On a replica:** the same screen instead names the primary it follows, how
long since its last sync, and a Promote button behind a confirmation carrying
the warning from Task 7.

**On both:** the dashboard gains a replication line — role, and either peer
count or sync age.

- [ ] **Step 1: Write the failing tests**

```go
func TestPrimaryReplicasScreenListsPeers(t *testing.T)
func TestReplicaScreenNamesItsPrimaryAndSyncAge(t *testing.T)
func TestInviteDisplaysCodeAndFingerprintTogether(t *testing.T)
func TestPromoteButtonCarriesTheWarning(t *testing.T)
func TestStandaloneNodeHidesTheScreen(t *testing.T)
```

`TestInviteDisplaysCodeAndFingerprintTogether` matters: an operator who is
shown a code without the fingerprint cannot complete `join` safely on the
other machine, and will be tempted to skip the check.

- [ ] **Step 2: Run to verify failure**

- [ ] **Step 3: Implement**

Follow the existing page/template/handler split. Reuse the Task 5 and 7
handlers rather than duplicating their logic in the web layer.

- [ ] **Step 4: Run the tests**

- [ ] **Step 5: Commit**

```bash
git add internal/web/
git commit -m "feat(web): a screen for replicas, invites, and promotion"
```

---

### Task 9: End to end, and the docs

**Files:**
- Create: `internal/app/replication_e2e_test.go`
- Modify: `README.md`, `DESGINE.md`, `docs/superpowers/specs/2026-08-13-kydns-linked-server-replication-design.md`

The spec's full sequence, two nodes in one process, driven through the real
CLI and API rather than by writing store rows:

- [ ] **Step 1: Write the failing test**

```go
// The whole feature, end to end, the way an operator meets it.
func TestOperatorPairsWritesFailsOverAndPromotes(t *testing.T) {
	// 1. Start a primary and a standalone node.
	// 2. Mint an invite on the primary; join from the other node using the
	//    fingerprint the invite reported.
	// 3. Add a service on the primary; assert the replica RESOLVES it.
	// 4. Assert a write against the replica's admin API is refused with 409.
	// 5. Stop the primary; assert the replica still resolves the name and
	//    reports health as unknown rather than stale-good.
	// 6. Promote the replica; assert it now accepts a write.
	// 7. Restart it; assert it is still a primary.
}
```

Assert on resolved DNS answers, not table rows. A row that appears without the
zone snapshot being rebuilt is the integration bug this test exists to catch,
and part 1's end-to-end test caught exactly that class of problem.

- [ ] **Step 2: Run to verify failure**

- [ ] **Step 3: Make it pass**

- [ ] **Step 4: Update the documentation**

- README "What works today": replication is now operable — pairing, promotion,
  and the replica screen. Say plainly what is still absent: no automatic
  failover, no peer discovery, one primary only.
- `DESGINE.md`: the replication section is no longer deferred. Rewrite the
  tense and drop the "None of this section is implemented" opener.
- The spec: mark `GET /replica/health-status` implemented, and record
  promotion's database-recorded persistence, which the spec does not currently
  describe.

- [ ] **Step 5: Run everything**

```bash
make test && make build && go vet ./... && gofmt -l .
```

- [ ] **Step 6: Commit**

```bash
git add internal/app/ README.md DESGINE.md docs/
git commit -m "test(app): pair, fail over, and promote end to end

Drives the real CLI and API, and asserts on resolved answers rather than
table rows."
```

---

## Self-review

**Spec coverage.** Write gate → Tasks 2, 3. Read paths stay open → Task 3.
Health replication and unknown-when-unreachable → Task 4. CLI verbs
invite/join/list/remove/promote → Tasks 5, 6, 7. Dashboard and staleness
banner → Tasks 3, 8. Promotion warning and demotion → Task 7. The spec's full
test sequence → Task 9.

Every part-1 parked finding is assigned: Puller wiring → 1, `PutPeer` label →
5, `reachable()` ordering → 4, dial timeout assertion → 6.

**Not in this plan, and deliberately:** automatic failover, leader election,
peer discovery, more than one primary, an administrative audit log. All are
listed out of scope in the spec.

**Type consistency.** `Role` and its three constants are defined once in Task
1 and consumed by 2, 3, 5, 7, 8. `ReplicaStatus` is the single shape the API
and both UI surfaces render. `replica.Status` (part 1) is the puller's
internal type and is converted at the `internal/app` boundary, not leaked into
`adminapi`.

**Known soft spot.** Tasks 3 and 8 specify test names and behaviour rather
than full bodies, because both must be written against the existing template
and handler structure, which needs reading first. Each names the files to read.

**Ordering.** 1 gates everything. 2 before 3 (the API gate is the simpler
shape to get right first). 5 before 6 (join needs an invite to redeem). 7
after 6 (demotion is join on a former primary). 8 after 5 and 7 (it renders
their handlers). 9 last.
