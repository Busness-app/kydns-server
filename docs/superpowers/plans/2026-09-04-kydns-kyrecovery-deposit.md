# KyDNS shared primitives and KyRecovery deposit implementation plan

Plan, 2026-09-04. Repo `kydns-server`, branch `feat/kyrecovery-deposit`.

## Goal

Adopt the suite's dependency-free `ky-primitives` module for password policy and
recovery capsules, then add a complete KyRecovery pairing, export, deposit, drill,
and restore path without changing KyDNS's DNS, replication, or import/export behavior.

## Sources of truth

- Shared types and compatibility: `github.com/Busness-app/ky-primitives@v0.4.1`.
- Wire protocol and limits: `kyrecovery-server/zero_code_pairing_handoff_spec.md`.
- Product-side implementation: current `ky_server_base/internal/backup` plus the
  hardened behavior recorded in MySlop folder `kydns-kyrecovery-deposit`.
- KyDNS architecture and verification: this repository's `AGENTS.md` and child index.

Copy only product-specific orchestration. Import capsule, password, and recovery-key
primitives from `ky-primitives`; do not create another shared-library fork inside KyDNS.

## Decisions fixed before implementation

- SQLite is the only supported store, so snapshots use the live `*sql.DB` handle and
  `VACUUM INTO`. Copying `kydns.db` is invalid in WAL mode.
- A capsule contains `kydns.db`, `node_key`, the three-key YAML manifest, and the
  existing secret-free export document. Missing required members fail closed.
- The node identity key is included so a restored node keeps its replica identity.
- KyRecovery's token is encrypted at rest with a node-local 32-byte deployment key in
  `data_dir/backup_key`; the database stores only the sealed value. The key file is
  mode `0600`, created atomically, and included in the capsule only through sealing to
  the independently pinned KyRecovery public key.
- Backup settings and audit rows are node-local and absent from replication snapshots.
- Existing admin sessions protect browser routes. Every state-changing browser route
  uses the existing CSRF middleware. API-token access uses `/api/v1/...` and does not
  rely on cookies. KyDNS has no MFA/step-up model, so none is invented in this change.
- Deposits continue after the initiating request or SIGTERM cancellation, with a
  16-minute deadline and a per-process single-flight guard. Scheduled deposits default
  to 24 hours, reject nonzero intervals below 15 minutes, and may be disabled with `0`.
- A paired node whose pinned recovery key is missing returns `ErrKeyPinMissing` and is
  audited; it is never treated as silently unpaired.
- Recovery URLs require HTTPS, a hostname without userinfo/query/fragment, public DNS
  results, and no private, loopback, link-local, multicast, documentation, CGNAT,
  benchmarking, reserved, or IPv4-mapped blocked addresses. HTTP redirects are refused.
- The stale root pairing-spec copy is deleted after links point to KyRecovery's copy.

## Task 1: Pin the shared module and prove password compatibility

Files: `go.mod`, `go.sum`, `internal/auth/password.go`,
`internal/auth/password_test.go`.

1. Raise the Go directive to `1.26.6` and add
   `github.com/Busness-app/ky-primitives v0.4.1`.
2. Replace KyDNS's PHC encoder and verifier with the shared password package while
   retaining `auth.HashPassword`, `auth.VerifyPassword`, and `MinPasswordLen` as the
   local API used by setup, reset, and login.
3. Add a compatibility test that verifies an existing KyDNS Argon2id fixture with the
   shared verifier and verifies a newly generated shared hash through the KyDNS wrapper.

Complete when `go test ./internal/auth` passes and no local Argon2 parameter constants or
PHC parser remain.

## Task 2: Add node-local settings, audit, and consistent snapshots

Files: `internal/store/store.go`, new `internal/store/backup.go`, new
`internal/store/backup_test.go`, and `internal/store/apply_test.go`.

1. Add node-local tables:
   - `local_settings(key TEXT PRIMARY KEY, value TEXT NOT NULL)` for the recovery URL,
     sealed token, pinned key fingerprint, and last receipt.
   - `audit_events(id, actor, action, resource, details, ip, outcome, created_at)` with
     bounded strings and an index on `created_at`.
2. Add narrow store methods: `GetLocalSetting`, `SetLocalSetting`, `DeleteLocalSetting`,
   `RecordAudit`, and `SnapshotTo`. Reuse `store.ErrNotFound` for an absent key.
3. Implement `SnapshotTo` with a validated absolute destination and SQLite
   `VACUUM INTO`; callers own cleanup of the private temporary directory.
4. Prove an uncheckpointed WAL row appears in the snapshot and prove backup/audit tables
   are not copied by replication apply.

Complete when the store tests pass under `-race`, including the WAL assertion.

## Task 3: Port the hardened backup package around `ky-primitives`

Files: new `internal/backup/AGENTS.md`, `capsule.go`, `client.go`, `deposit.go`,
`drill.go`, `recoverykey.go`, and focused tests beside them.

1. Adapt the current scaffold package to KyDNS interfaces instead of importing scaffold
   packages. Keep one concrete store dependency; avoid factories and speculative driver
   interfaces.
2. Build the capsule from a live database snapshot, `node_key`, `backup_key`, the config
   manifest, and the existing export representation. Normalize paths and reject duplicate,
   absolute, escaping, oversized, or missing required members before sealing.
3. Seal and parse with `ky-primitives/capsule`; pin the Ed25519 recovery public key and
   derive its displayed fingerprint through `ky-primitives/recoverykey`.
4. Store pairing atomically where possible: pinned key first, then URL and encrypted
   token. If later storage fails, preserve and audit the pin so a new key cannot replace it
   unnoticed. Re-pairing to a different key is refused.
5. Implement claim and deposit clients with bounded response bodies, timeouts, explicit
   content types, redirect refusal, DNS/IP validation on every dial, one-time-token
   persistence, and KyRecovery receipt verification for capsule ID, digest, and size.
6. Record a receipt only after verification. Distinguish local seal failure,
   `ErrNotPaired`, `ErrKeyPinMissing`, `ErrRemote`, `ErrReceiptUnrecorded`, and
   `ErrDepositInProgress`. Centralize bounded audit fields in `Outcome`.
7. Implement a restore drill in a mode-`0700` temporary directory. It opens the capsule,
   validates every manifest member, runs SQLite integrity checking, checks the export and
   key files, then removes the sandbox.
8. Add a source-walk guard using an absolute repository root and a file-count floor. Only
   the restore command and drill function may decrypt/combine recovery material.

Complete when package tests prove: private-key-only opening, WAL preservation, plaintext
token absence, different-key re-pair refusal, redirect refusal, reserved-range refusal,
receipt mismatch refusal, single-flight behavior, and a non-vacuous decrypt guard.

## Task 4: Add backup configuration

Files: `internal/config/config.go`, `internal/config/config_test.go`,
`kydns.example.yaml`, and `internal/config/example_test.go`.

1. Add runtime-only `BackupDepositInterval`, seeded from
   `KYDNS_BACKUP_DEPOSIT_INTERVAL` with `24h` default, `0` disabled, and 15-minute floor.
2. Keep it out of YAML because it controls node-local operational scheduling, not shared
   DNS configuration. Document it as an environment override.
3. Test default, disabled, malformed, negative, below-floor, and valid values.

Complete when config and example-contract tests pass without expanding the YAML-owned key
set.

## Task 5: Expose authenticated API operations

Files: new `internal/adminapi/backup.go`, tests, and small wiring changes in
`internal/adminapi/api.go` and `internal/app/serve.go`.

1. Attach a backup service to `adminapi.API` through one optional `WithBackup` method so
   existing unit fixtures remain small.
2. Register:
   - `POST /api/v1/backup/drill`
   - `GET /api/v1/backup/export-capsule`
   - `POST /api/v1/backup/pair-remote`
   - `POST /api/v1/backup/deposit`
   - `GET /api/v1/backup/status`
3. Use existing bearer-token authentication and write gating. Export refuses success when
   its audit record cannot be written. Resolve the acting token label before detaching a
   deposit context, then audit every outcome on that detached context.
4. Return `412` for unpaired or missing-key state, `409` for an in-flight deposit, `400`
   for invalid input, `502` for a refused remote operation, and `500` only for local faults.
   Responses never include the recovery token or encrypted token.

Complete when route tests prove authentication, replica write refusal, status redaction,
error mapping, audit-on-every-result, and export audit failure behavior.

## Task 6: Add server-rendered operator controls

Files: `internal/web/pages.go`, new `internal/web/backup.go`, relevant template and tests,
plus existing embedded CSS only if a reusable class cannot express the layout.

1. Add a Backup section to the settings page rather than creating a second application
   shell. Show pairing state, pinned fingerprint, last verified receipt, and drill status.
2. Add CSRF-protected form handlers for pair, deposit-now, and drill. Export remains a
   logged-in download route and must audit before writing bytes.
3. Reuse the current flash/error and form patterns. Never render either form of the token.
4. Make all controls usable by keyboard and preserve visible labels and status text.

Complete when web tests prove anonymous rejection, CSRF rejection, successful actions,
safe escaping, token non-disclosure, and rendering at narrow layouts.

## Task 7: Add CLI operations and the scheduler

Files: `cmd/kydns/main.go`, tests, `internal/cli` only where the existing API client is the
right transport, and `internal/app/serve.go`.

1. Add `backup-drill`, `export-capsule`, and `deposit` as API-backed commands consistent
   with the existing CLI token/config behavior.
2. Add local `restore --capsule PATH --out DIR`; read custodian shares from stdin, never
   argv or environment, require an empty/nonexistent output directory, and create restored
   files with restrictive permissions.
3. Start a scheduler from `Serve` only when the interval is nonzero. Wait one full interval
   before the first deposit, use `context.WithoutCancel` for an upload already started,
   apply the 16-minute deadline, and silently skip only a never-paired node.
4. Audit scheduler and CLI outcomes through the same `backup.Outcome` path as HTTP.

Complete when command tests cover usage and stdin handling, and scheduler tests use a fake
clock/ticker or injected one-shot function without waiting in real time.

## Task 8: Documentation and DOX pass

Files: `AGENTS.md`, `README.md`, `DESGINE.md`, `SECURITY.md`, `LOGGING.md`,
`CONTRIBUTING.md`, and deletion of `zero_code_pairing_handoff_spec.md`.

1. Document the operator workflow, schedule override, restore command, capsule contents,
   threat boundary, redaction rules, and verification commands.
2. Add `internal/backup` to the package ownership index and state that backup settings,
   audit, keys, and receipts never replicate.
3. Replace the stale local protocol document with a link to the authoritative KyRecovery
   copy; correct the existing claim that KyDNS already owns pairing/push endpoints.
4. Check every Child DOX Index entry touched by the behavior and remove stale statements.

Complete when documentation names only routes and commands that exist and the example
configuration contract remains green.

## Task 9: Final verification and delivery

Run, in order:

```sh
gofmt -w <modified-go-files>
go mod tidy
go vet ./...
go test -race ./...
go test ./internal/backup -run 'TestDecryptGuard' -count=1
git diff --check
```

Then perform a local smoke test with temporary data: start KyDNS, create the admin, verify
an unpaired export/deposit returns `412`, and confirm ordinary DNS plus registry export
still work. A real end-to-end pair/deposit against deployed KyRecovery is a separate
deployment check because the client correctly rejects loopback and plain HTTP.

Complete when the worktree is clean after a commit, CI is green, the security reviewer is
cleared, and the MySlop folder contains the PR URL, current commit, remaining deployment
check, and any non-blocking follow-ups.

## Hard stops

- Stop if `ky-primitives` cannot verify an existing KyDNS password hash; that is a password
  migration decision, not a refactor.
- Stop if an existing KyRecovery key/capsule fixture does not round-trip through v0.4.1;
  changing an on-disk recovery format requires a suite-wide compatibility decision.
- Stop if the existing export representation cannot be produced without an HTTP response
  writer; extract the shared serialization root once, then keep both HTTP export and capsule
  collection on it rather than parsing KyDNS's own HTTP output.

