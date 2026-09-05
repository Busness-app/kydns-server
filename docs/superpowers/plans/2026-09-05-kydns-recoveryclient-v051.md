**Repo:** kydns-server
**PR:** #30 — https://github.com/Busness-app/kydns-server/pull/30 (merged predecessor; no migration PR yet)
**Worktree:** /home/yoshi/busness.app/kydns-server (main, 14839aea5a383d490fba7e2dc858424b12b91c39)

# KyDNS recoveryclient v0.5.1 migration plan

Prepared 2026-09-05 from myslop post 292. Claimed by `juniper` in
`kydns-kyrecovery-deposit` (claim post 301). Yoshi subsequently authorized execution.
The steps below are the acceptance criteria; implementation and live proof are
reported separately in the completion record.

## Verified starting point

- Fetch completed; local main and origin/main are at the SHA above. The checkout
  was clean before adding this plan and its DOX index entry.
- `go.mod` pins ky-primitives v0.5.0. The local library tag v0.5.1 resolves to
  `e9bd63b44ea62b98340a90e18a35e2ffd8d21f66`; its drill callback takes
  `func(dir string, opened capsule.Manifest) []recoveryclient.Check`.
- `internal/backup/backup.go` passes `drillChecks(p)`, closing over the collected
  files. It checks existence and one fixed database path; it does not validate
  the opened recipe or key/config contents.
- Both API and web drill handlers call the same `Service.Drill`; that service
  currently has no drill serialization. Put the guard there to cover both callers.
- `store.VerifySnapshot` opens read-only, checks SQLite integrity and the KyDNS
  `services` and `local_settings` tables. Reuse it; opening via `store.Open`
  would create or migrate the artifact being tested.
- Existing tests cover empty databases, successful drills, pinning, local copies,
  scheduling, unpairing, token secrecy, headers, and replica refusal. They do not
  establish compatibility with ciphertext produced by the old dependency version.
- `scripts/backup-live-proof.sh` uses a disposable server and local destination;
  it never deposits to KyRecovery. `scripts/restore-drill.sh` proves CLI extraction
  and rejection paths using a placeholder database, not a usable restored service.

## 1. Establish the migration branch and compatibility fixture

Re-read the board claim and applicable AGENTS.md chain before implementation.
Preserve unrelated edits and create `fix/recoveryclient-v051` from refreshed main.
If the source has changed, reconcile this plan with that source before editing.

Using an isolated helper module pinned to v0.5.0, produce a small fixture with a
synthetic deployment key, synthetic token, and sealed pairing settings. Commit
only explicitly synthetic fixture data and its provenance to backup testdata.
Retain the existing contracts: file `backup_key`, label `KyDNS:kyrecovery_token`,
and row `kyrecovery_token_enc`. Existing legacy-row cleanup stays unchanged.

Then run `go get github.com/Busness-app/ky-primitives@v0.5.1` and `go mod tidy`.
Inspect the resolved module API and dependency diff before adapting the callback.

Done when the version resolves to the intended release, the fixture demonstrably
comes from v0.5.0, and only the intended dependency changes remain. Pairings from
PR #27's older format remain subject to the documented same-key re-pair procedure.

## 2. Validate the opened drill manifest and restored members

Primary files: `internal/backup/backup.go` and `backup_test.go`.

Replace the captured-payload callback with `drillChecks(dir, opened)`. Keep product
checks local and use the library for sealing, extraction, and scratch cleanup.
Validate the authenticated manifest's service name and recipe before filesystem
access. JSON-decoded lists are `[]any`; require string elements explicitly.

Require `check_sqlite_integrity: true`, a nonempty `sqlite_paths` containing
`data/kydns.db`, and `required_files` containing `data/kydns.db`,
`data/backup_key`, and `config/kydns.yaml`. Optional identity/pin members present
in the opened manifest must also be required and validated. Missing fields,
wrong types, empty lists, or omitted mandatory entries produce failed checks.
Use small validation helpers only where they remove duplicated boundary checks.

Accept only clean relative slash paths inside the extraction root: reject empty,
absolute, traversal, backslash, and noncanonical paths. Require referenced members
to be listed in the opened manifest and to exist as regular restored files;
refuse symlinks and directories. Validate all paths before reading any member.

Validate real contents:

- Run `store.VerifySnapshot` for each declared SQLite path.
- Require the restored `backup_key` to decode to 32 bytes using `keyfile.Load`.
  The existing file is hex-encoded, as confirmed by the v0.5.0 compatibility test.
- Decode the restored YAML and validate the three owned settings against existing
  config rules without creating files or reading live environment defaults.
- For included `node_key`, enforce the existing Ed25519 seed format without
  calling its load-or-create path.
- For included `recovery.pub`, use the library's parsing/validation contract;
  check its identity against restored pin settings through read-only access.
- When restored settings contain a pairing, prove its token decrypts with the
  restored backup key and existing label; keep plaintext out of checks and logs.

Serialize `Service.Drill` across collection and the library call with a service
mutex; check cancellation after acquiring it. This is one process-wide Service
in current app wiring. Keep scratch under DataDir, owner-only, and cleaned on exit.

Done when malformed recipes cannot silently skip checks, corrupt required
contents fail, valid capsules pass, and both product entry points share the guard.

## 3. Prove migration behavior with focused tests

Extend existing tests rather than create another verification framework.

| Area | Required evidence |
| --- | --- |
| Opened recipe | A real seal/open drill exercises JSON `[]any`; nil/wrong-type recipes, mixed list types, missing flags, omitted required paths, and empty lists fail. |
| Path boundary | Absolute/traversal/backslash/noncanonical paths, unlisted members, directories, and symlinks fail before outside files are read. |
| Restored content | Missing files, empty/corrupt/non-KyDNS SQLite, malformed YAML, short keys, invalid public pin, and undecryptable pairing fail. Optional members may be absent only when the capsule does not declare or require them. |
| Compatibility | Load the fixed v0.5.0 pairing fixture through `New` and current library APIs; assert the expected synthetic token and unchanged key/pin/URL/sealed row after reconstruction. Do not generate the old ciphertext with v0.5.1. |
| Lifecycle | Concurrent calls complete without overlapping drill work; scratch permissions and cleanup hold on success/failure; waiting cancellation prevents a new drill. |

Use a deterministic concurrency check at the shared service boundary; avoid
timing-only sleeps or a production dependency-injection framework for one test.
Retain API/web failed-drill audit behavior and existing CSRF/header regressions.

Done when focused tests pass under the race detector and demonstrate each failure
at its actual boundary. Preserve read-only snapshot verification.

## 4. Run repository and disposable recovery verification

After implementation, run:

```sh
gofmt -w internal/backup/backup.go internal/backup/backup_test.go
go mod tidy
go vet ./...
go test -race -timeout 10m ./...
CGO_ENABLED=0 go build -trimpath -o /tmp/kydns-v051 ./cmd/kydns
go test ./internal/backup -run TestNothingInTheServerDecrypts -count=1
bash scripts/backup-live-proof.sh
bash scripts/restore-drill.sh
git diff --check
```

Include any new Go files in gofmt. Verify tidy produces no subsequent diff.
Prove the decrypt guard by temporarily planting a forbidden call in a non-test
source file, observe failure, remove the probe, and confirm it passes again.
The existing allowlist names `cmd/kydns/main.go:run`; do not broaden it.

Read script cleanup and prerequisites before running. The local proof requires
curl, sqlite3, Go, and free loopback ports (defaults 15353/18053); use its port
overrides if occupied. Leave its data directory override unset for a fresh fixture.
Both scripts delete their own scratch and helper directories.

Extend the restore fixture to use a real KyDNS snapshot and a sentinel record,
then restore with synthetic shares and verify the snapshot and sentinel. Preserve
existing negative CLI cases. Synthetic shares stay local to disposable fixtures;
real custodian shares are entered locally on stdin, never chat/argv/shared files.

Done when local gates and both scripts pass, including real database restore proof.
This evidence does not establish live KyRecovery delivery or real-card recovery.

## 5. Documentation and review delivery

Update `internal/backup/AGENTS.md` for opened-manifest checks, serialization, and
compatibility verification. Update `docs/RESTORE.md` if the script's proof changes;
remove the stale “once Phase B lands” schedule comment in docker-compose.yml.
Keep root DOX links current. Leave unrelated syncauth/oidcverify and library API
follow-ups outside this migration; KyDNS already has an OIDC surface, so any
future migration requires its own assessment.

Open one migration PR using the repository pull-request workflow. Require all
applicable CI jobs (tests, cgo-free build, Docker, package matrices, Raspberry Pi
image) and current-head reviewer clearance. Report the exact tested commit SHA
for human merge. Do not call a fixture run a deployed-system proof.

Done when the PR is reviewable and green at its final SHA with documentation
aligned. Keep live proof separately outstanding until step 6 succeeds.

## 6. Verify the actual homelab deployment

Before changing the deployment, identify its host/project, running image revision, volume,
mounts, DNS settings, and existing backup status without exposing credentials.
Prepare the exact reviewed image and volume-preserving deployment command for
the intended host. Record readiness and a known DNS answer before the change.

For the intended private KyRecovery, preserve existing settings and use
`KYDNS_BACKUP_ALLOW_PRIVATE_RECOVERY=true`, `KYDNS_DNS=192.168.1.1`, and
`docker-compose.lan-dns.yml`. For a source deployment the command shape is:

```sh
KYDNS_BACKUP_ALLOW_PRIVATE_RECOVERY=true KYDNS_DNS=192.168.1.1 \
  docker compose -f docker-compose.yml -f docker-compose.lan-dns.yml \
  up -d --build kydns
```

Run it only in the confirmed deployment project with its existing overrides and
reviewed source revision. Verify readiness, actual image identity, container DNS,
and unchanged production DNS behavior. Preserve the data volume, issuer, keys,
pin, and pairing. Retain the previous image for a volume-preserving rollback if
readiness or DNS checks regress; do not remove volumes or recreate identities.

Use `https://kyrecovery.urlxl.us`; compare the pin fingerprint out of band. An
existing pairing must deposit without re-pairing. If previously unpaired, obtain
a fresh code through the existing admin workflow and label this first-pair proof.
Record capsule ID, locally computed digest matched to the receipt/dashboard,
receipt time, pinned key ID, deployed SHA/image, and local-copy outcome (or that
no local destination was configured). Keep second-key, unpair, and schedule
mutation tests on disposable fixtures.

Done when the deployed revision is identified, the same pairing delivers a
verified receipt (or first-pair evidence is explicitly labeled), normal DNS still
works, and synthetic scratch restore succeeds. A real custodian-card restore is
a separate operator exercise and must never be inferred from synthetic results.

## Completion record

Mirror this plan and subsequent durable handoffs to the existing myslop folder.
Keep the claim under `juniper` while this work is reserved. Future closeout records
must distinguish code/CI, disposable recovery proof, deployed deposit proof, and
any outstanding real-card exercise, with exact tested revisions and no credentials.
