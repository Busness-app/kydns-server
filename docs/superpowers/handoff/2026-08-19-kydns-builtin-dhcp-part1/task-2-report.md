# Task 2 report: Settings columns and the lease table

## What changed

- `internal/store/model.go`: `Settings` gained `DHCPEnabled bool`, `DHCPInterface`,
  `DHCPRangeStart`, `DHCPRangeEnd`, `DHCPGateway string`, `DHCPLeaseSeconds int`,
  `DHCPSecondaryDNS string`, exactly as specified. Added the new `DHCPLease` struct
  (`MAC, IP, Hostname string; ExpiresAt, LastSeen int64`) at file end.
- `internal/store/store.go`:
  - Base `settings` table gained the 7 `dhcp_*` columns, with SQL-level defaults
    `dhcp_enabled=0`, `dhcp_lease_seconds=86400`, everything else `''`.
  - New `dhcp_leases` table (mac PK, ip UNIQUE, hostname, expires_at, last_seen),
    placed right after the `settings` table and before `config_version`/the `cv_`
    trigger block. No `cv_dhcp_leases_*` trigger.
  - `cv_settings_u`'s `WHEN` clause is untouched — no `dhcp_*` column named there.
    Updated the comment above it to say so explicitly.
  - Fourth migration entry: 7 `ALTER TABLE settings ADD COLUMN ...` statements plus
    `CREATE TABLE IF NOT EXISTS dhcp_leases (...)`, matching the base schema exactly.
  - `ApplySnapshot` (line ~924) — **not listed in the brief's file/step list, but
    required by the global constraint**; see "Deviation" below.
- `internal/store/settings.go`: `Settings()` and `putSettings` extended to
  read/write the 7 new columns (SELECT/Scan list, INSERT column list, 7 more `?`
  placeholders, 7 `excluded.` assignments, 7 trailing args).
- `internal/store/settings_test.go`: added `TestSettingsRoundTripsDHCPFields` and
  `TestDHCPSettingsDoNotBumpConfigVersion`, exactly as given in the brief except
  for the `reflect.DeepEqual` fix (see Corrections below).
- `internal/store/store_test.go`: extended `TestOpenMigratesAnOlderDatabase` (did
  **not** add a third migration test — corrections applied).
- `internal/store/apply_test.go`: extended `TestApplySnapshotPreservesNodeLocalSettings`
  to also assert the 7 DHCP fields survive an apply (see Deviation below).

## Corrections from the task brief (as instructed, applied without asking)

1. `openTestStore(t)` → used `open(t)` (store_test.go:10). Confirmed brief's helper
   name doesn't exist; `open` is the real one, used consistently by every other
   test in the package.
2. `if got != v` → `reflect.DeepEqual(got, v)` in `TestSettingsRoundTripsDHCPFields`.
   Confirmed `store.Settings` contains `[]string` fields (`ReverseZones`,
   `Upstreams`, `AllowQuery`); `go vet` reports "struct containing []string cannot
   be compared" on `==`. Matches the settings_test.go idiom already used by
   `TestSettingsRoundTrip` (`reflect.DeepEqual`, `t.Errorf` with `%+v` on both sides).
3. Step 8 migration test: did not add a third test. Extended the existing
   `TestOpenMigratesAnOlderDatabase` (store_test.go:216) instead. That test builds
   a hand-rolled legacy `services`-only database, opens it (which runs every
   migration including the new one), then — since the DHCP proof needed a settings
   row and this legacy DB has none — inserts a settings row *without* naming any
   `dhcp_*` column, so the values that come back are whatever the `ALTER ... DEFAULT`
   actually wrote, not whatever Go supplied. Asserts `DHCPEnabled == false`,
   `DHCPLeaseSeconds == 86400`, and the four string fields `== ""`. Then inserts a
   row into `dhcp_leases` directly via `s.db.Exec` to prove the table exists. This
   runs inside the *first* `Open()` in that test, before the reopen section, since
   that's the Open call that actually executes the ALTERs (`fresh == false` because
   `services` pre-existed).

   I did not touch `TestMigrationsAreIdempotent` — it only opens/closes a fresh
   database twice and has no schema-specific assertions to extend.

## One deviation beyond the brief: `ApplySnapshot`

Not in the brief's file list, not in the "Corrections" section, and not called out
anywhere in the plan or spec docs I could find — but the task's own binding global
constraint says "DHCP settings are node-local and must never replicate," and I found
a live way that promise would break the moment this task's fields exist:

`internal/app/replication.go`'s `storeSource.Snapshot()` reads the *entire* local
`Settings()` row (DHCP fields included) on the primary and ships it whole inside
`store.SnapshotInput`. `Store.ApplySnapshot` on the replica already has a
node-local-field-preservation block — it re-reads `dhcp_lease_file`,
`discovery_interval`, `log_queries`, `log_client_ip` from the replica's own row and
overwrites whatever the incoming snapshot carried for those four, specifically so a
verbatim-forwarded pulled document can't wipe them. That block did not know about
the 7 new `dhcp_*` fields. Since `cv_settings_u`'s `WHEN` clause never names them,
a config-version bump doesn't require a DHCP field to change — any other replicated
setting changing (e.g. TTL) triggers a snapshot pull, and that snapshot carries the
*primary's* DHCP config (or a zero value, if the primary's own DHCP is unconfigured)
straight into the replica's local settings row, overwriting whatever the replica
had configured for its own DHCP server. That's not a future risk gated behind
later tasks — replication and `ApplySnapshot` are already live code paths today.

Fix: extended the same preservation block in `ApplySnapshot` (store.go) to also
re-read and re-apply all 7 `dhcp_*` columns, mirroring the existing pattern exactly
(same query-then-overwrite shape, same comment updated to name all node-local
columns). Extended `TestApplySnapshotPreservesNodeLocalSettings` (apply_test.go) to
set different DHCP values on both the local and incoming settings and assert the
local values survive the apply.

I did this rather than only flagging it because: it's in the same file already
being edited for this task, the fix is the established pattern applied to more
columns (no new design decision), and leaving it unfixed would mean this task
shipped code that visibly contradicts the constraint stated as binding for it. If
this should instead have been owned by a later task (e.g. one of T9-T11 touch
replication/apply), it's easy to revert — it's isolated to the diff in
`ApplySnapshot` and its one test.

## Process notes

- Worked test-first per the brief's step order: wrote the two new settings tests,
  ran them and confirmed the expected compile failure
  (`v.DHCPEnabled undefined (type Settings has no field or method DHCPEnabled)`),
  then implemented model → schema → migration → settings.go in that order, then
  reran to green.
- Left the base-schema/migration duplication alone per instructions — a fresh
  database takes the base schema and skips migrations (see `migrate()`'s
  `freshDB` branch), so the columns have to exist in both places.
- Did not touch `cv_settings_u`'s WHEN clause or add any `cv_` trigger on
  `dhcp_leases` — verified with `grep -n "cv_settings_u" -A20` and
  `grep -n "cv_dhcp"` (no match).

## Commands run and output

```
$ go test ./internal/store/ -run 'TestSettingsRoundTripsDHCP|TestDHCPSettingsDoNot' -v
# --- before implementation ---
internal/store/settings_test.go:15:4: v.DHCPEnabled undefined (type Settings has no field or method DHCPEnabled)
... (7 more, same shape)
FAIL	github.com/yoshiofthewire/kydns-server/internal/store [build failed]

# --- after implementation ---
=== RUN   TestSettingsRoundTripsDHCPFields
--- PASS: TestSettingsRoundTripsDHCPFields (0.00s)
=== RUN   TestDHCPSettingsDoNotBumpConfigVersion
--- PASS: TestDHCPSettingsDoNotBumpConfigVersion (0.00s)
PASS

$ go test ./internal/store/... -count=1 -v
... (58 tests, all PASS, including TestOpenMigratesAnOlderDatabase,
     TestMigrationsAreIdempotent, TestApplySnapshotPreservesNodeLocalSettings,
     TestSettingsSplitBumpsOnlyForReplicatedKeys)
ok  	github.com/yoshiofthewire/kydns-server/internal/store	0.169s

$ go vet ./internal/store/
(clean, exit 0)

$ go vet ./...
(clean, exit 0)

$ go build ./...
(clean, exit 0)

$ go test ./... -count=1
ok  	.../cmd/kydns          0.005s
ok  	.../internal/adminapi  0.255s
ok  	.../internal/app       24.364s
ok  	.../internal/auth      0.514s
ok  	.../internal/cli       0.028s
ok  	.../internal/config    0.009s
ok  	.../internal/discovery         0.361s
ok  	.../internal/discovery/dhcp    0.004s
ok  	.../internal/dnsserver 0.171s
ok  	.../internal/health    0.241s
ok  	.../internal/policy    0.206s
ok  	.../internal/registry  0.044s
ok  	.../internal/replica   0.344s
ok  	.../internal/settings  0.007s
ok  	.../internal/store     0.202s
ok  	.../internal/upstream  0.112s
ok  	.../internal/web       16.133s
ok  	.../internal/zone      0.004s
```

All 18 packages green, matching the baseline noted in progress.md (18 packages ok,
0 failures, vet clean).

## Left alone

- `TestMigrationsAreIdempotent` — no schema-specific assertions to extend for this
  task; it only proves reopen is safe in general.
- `TestSettingsSplitBumpsOnlyForReplicatedKeys` (version_test.go) — already proves
  the node-local/replicated split pattern via `LogQueries`; `TestDHCPSettingsDoNotBumpConfigVersion`
  is the dedicated proof for the DHCP columns, so this test needed no change.
- `internal/store/dhcplease.go` (CRUD for `DHCPLease`) — explicitly Task 3, not
  this task. `DHCPLease` the type exists now; `DHCPLeases()/PutDHCPLease()/...`
  do not.
- Everything downstream of `store.Settings` (admin API, DHCP runner, validation) —
  out of scope per the brief; `go build ./...` confirms nothing else references
  the new fields yet, so there was nothing to update.
