# KyDNS backup to suite spec via ky-primitives/recoveryclient — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring KyDNS's KyRecovery backup integration (merged in PR #27) up to the suite spec by wiring the `ky-primitives/recoveryclient` package (v0.5.0) instead of growing the hand-rolled `internal/backup`, and finish the product-side work that does not depend on it.

**Architecture:** Two phases. Phase A (unblocked today) commits the pending hardening diff, adds the product config and compose wiring, writes and proves the restore runbook, and fixes the docs. Phase B (on ky-primitives v0.5.0, which carries `recoveryclient`; tagged 2026-09-04 at 533a053) replaces the client, key pin, pairing record, drill and restore in `internal/backup` with thin calls into the library, then adds the spec items that build on it: unified `Run`, local backup directory, admin-set schedule, pin-by-hand, unpair, private-recovery opt-in, the rebuilt settings screen, and the decrypt guard.

**Tech Stack:** Go 1.26.6, `github.com/Busness-app/ky-primitives` (stdlib-only), modernc SQLite, Go `html/template` server-rendered UI, docker compose.

**Spec:** MySlop folder `kydns-kyrecovery-deposit` post 192 (the 14-row contract, KyDNS's "owes" list) and folder `ky-primitives-kyrecovery-package` posts 189, 200, 204, 208 and 211 (the library, built as `recoveryclient` in ky-primitives PR #12, tagged v0.5.0 at 533a053). Durable copies: `/home/yoshi/busness.app/AGENTS.md` section "KyRecovery integration", and `ky_server_base/docs/superpowers/plans/2026-09-04-bring-suite-to-kysignon-spec.md`. Reference implementation: `kysignon-server` master (`internal/backup/{schedule,local,deposit,client}.go`, `internal/api/backup_handlers.go`, `docs/RESTORE.md`, `docker-compose.lan-dns.yml`).

## Global Constraints

- Do not add a fifth copy of the product-side backup code. Items that the library will own (client, key pin, sealed pairing record, local copies, schedule, unified run, drill runner, restore, guard helper) are implemented only by calling `ky-primitives/recoveryclient`. Phase B codes against v0.5.0.
- `service_name` sent at pairing and passed to `capsule.Seal` is `KyDNS`, byte for byte.
- Key pin is write-once. A second pairing or pin to a different key fails with 409, never overwrites.
- HTTPS always. Redirects refused. Loopback, link-local, multicast, unspecified and reserved (`192.0.0.0/24`, `198.18.0.0/15`, `240.0.0.0/4`, `64:ff9b::/96`) refused unconditionally. Private and CGNAT (`100.64.0.0/10`) admitted only when `KYDNS_BACKUP_ALLOW_PRIVATE_RECOVERY=true`.
- Schedule bounds: `0` (off) or `[15m, 366d]`, checked on whole seconds before any `time.Duration` math.
- Local copies: `KyDNS.<capsule-id>.kycap`, mode 0600, temp+sync+rename; list and prune only files with the `KyDNS.` prefix; a local write failure never cancels the deposit.
- Unpair deletes the URL and sealed-token rows only. Key pin, receipts and the local directory stay. UI text says "rows removed; the credential is dead only when the KyRecovery admin revokes it".
- Never render or log the token in either form. Remote text and operator input pass through `AuditSafe` (printable, 200 chars) before reaching an error or audit row.
- Restore shares arrive on stdin, never argv or environment. Restore refuses a non-empty target directory.
- No inline `on*=` handlers in templates. Existing templates have none; keep it that way.
- Every task ends with `gofmt -l`, `go vet ./...`, `go test -race ./...` green and `git diff --check` clean before its commit.
- KyDNS has no step-up model. The product equivalent for destructive routes is: web routes behind `requireCSRF` (which wraps `requireSession`), API routes behind bearer `auth` plus the replica write gate. Every new mutating route is added to the write-gate test table.

---

## Phase A: unblocked now

### Task 1: Commit the pending hardening diff

**Files:**
- Modify (already modified in the working tree): `AGENTS.md`, `SECURITY.md`, `internal/adminapi/backup.go`, `internal/store/backup.go`, `internal/store/backup_test.go`, `internal/web/backup.go`

The working tree already holds a post-merge hardening change: `SnapshotTo` binds the `VACUUM INTO` path as a parameter instead of interpolating it, capsule downloads set `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`, and a store test proves a hostile path cannot inject SQL. Tests were run uncached and pass. Ship it before anything else so later diffs are readable.

- [ ] **Step 1: Confirm the diff is exactly the hardening change**

Run: `git diff --stat`
Expected: six files, 29 insertions, 4 deletions; no other files.

- [ ] **Step 2: Run the affected packages uncached**

Run: `go test -count=1 -race ./internal/store ./internal/backup ./internal/adminapi ./internal/web && git diff --check`
Expected: all `ok`, no whitespace errors.

- [ ] **Step 3: Branch and commit**

```bash
git switch -c fix/backup-snapshot-binding
git add AGENTS.md SECURITY.md internal/adminapi/backup.go internal/store/backup.go internal/store/backup_test.go internal/web/backup.go
git commit -m "fix(backup): bind the VACUUM INTO path and mark capsule downloads no-store

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

- [ ] **Step 4: Open the PR and drive it green**

Use the `pull-request` skill. Title: `fix(backup): bind the VACUUM INTO path and mark capsule downloads no-store`. Body: three bullets, one per change, plus the test name that proves the binding.

---

### Task 2: Backup config: directory, keep count, private-recovery opt-in

**Files:**
- Modify: `internal/config/config.go:33-35` (struct fields) and `:167-184` (`applyBackupEnv`)
- Test: `internal/config/config_test.go`
- Modify: `kydns.example.yaml` only if `internal/config/example_test.go` asserts the env-var comment block; otherwise leave it.

**Interfaces:**
- Produces: `Config.BackupDir string`, `Config.BackupKeep int` (default 7), `Config.BackupAllowPrivateRecovery bool` (default false), all `yaml:"-"`, populated only from `KYDNS_BACKUP_DIR`, `KYDNS_BACKUP_KEEP`, `KYDNS_BACKUP_ALLOW_PRIVATE_RECOVERY`. Tasks 6, 7, 8 and 9 read them.

- [ ] **Step 1: Write the failing tests**

Append to `internal/config/config_test.go` (follow the file's existing pattern for writing a temp YAML and calling `Load`; the helper is whatever the existing `KYDNS_BACKUP_DEPOSIT_INTERVAL` tests use):

```go
func TestBackupEnvDefaults(t *testing.T) {
	for _, k := range []string{"KYDNS_BACKUP_DIR", "KYDNS_BACKUP_KEEP", "KYDNS_BACKUP_ALLOW_PRIVATE_RECOVERY"} {
		t.Setenv(k, "")
	}
	c := loadMinimal(t)
	if c.BackupDir != "" || c.BackupKeep != 7 || c.BackupAllowPrivateRecovery {
		t.Fatalf("defaults = %q %d %v", c.BackupDir, c.BackupKeep, c.BackupAllowPrivateRecovery)
	}
}

func TestBackupEnvValues(t *testing.T) {
	t.Setenv("KYDNS_BACKUP_DIR", "/var/backups/kydns")
	t.Setenv("KYDNS_BACKUP_KEEP", "3")
	t.Setenv("KYDNS_BACKUP_ALLOW_PRIVATE_RECOVERY", "true")
	c := loadMinimal(t)
	if c.BackupDir != "/var/backups/kydns" || c.BackupKeep != 3 || !c.BackupAllowPrivateRecovery {
		t.Fatalf("got %q %d %v", c.BackupDir, c.BackupKeep, c.BackupAllowPrivateRecovery)
	}
}

func TestBackupEnvRejectsBadValues(t *testing.T) {
	for _, tc := range []struct{ k, v string }{
		{"KYDNS_BACKUP_KEEP", "0"}, {"KYDNS_BACKUP_KEEP", "-1"}, {"KYDNS_BACKUP_KEEP", "seven"},
		{"KYDNS_BACKUP_ALLOW_PRIVATE_RECOVERY", "yes"}, {"KYDNS_BACKUP_DIR", "relative/dir"},
	} {
		t.Run(tc.k+"="+tc.v, func(t *testing.T) {
			t.Setenv(tc.k, tc.v)
			if _, err := loadMinimalErr(t); err == nil {
				t.Fatalf("%s=%q accepted", tc.k, tc.v)
			}
		})
	}
}
```

If `loadMinimal`/`loadMinimalErr` do not exist, add them beside the existing interval tests: write `data_dir: <tmp>` to a temp file, call `Load`, and either `t.Fatal` on error or return it.

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/config -run 'TestBackupEnv' -v`
Expected: FAIL, `c.BackupDir undefined`.

- [ ] **Step 3: Implement**

In the `Config` struct after `BackupDepositInterval`:

```go
	// BackupDir, BackupKeep and BackupAllowPrivateRecovery are node-local process
	// policy from KYDNS_BACKUP_DIR, KYDNS_BACKUP_KEEP and
	// KYDNS_BACKUP_ALLOW_PRIVATE_RECOVERY. An empty BackupDir means no local copies.
	BackupDir                  string `yaml:"-"`
	BackupKeep                 int    `yaml:"-"`
	BackupAllowPrivateRecovery bool   `yaml:"-"`
```

In `applyBackupEnv`, after the interval handling and before `return nil`, replace the trailing `c.BackupDepositInterval = d; return nil` with a call into a new helper so the function stays readable:

```go
	c.BackupDepositInterval = d
	return c.applyBackupDestinationEnv()
}

func (c *Config) applyBackupDestinationEnv() error {
	c.BackupKeep = 7
	if v := strings.TrimSpace(os.Getenv("KYDNS_BACKUP_DIR")); v != "" {
		if !filepath.IsAbs(v) {
			return fmt.Errorf("KYDNS_BACKUP_DIR: %q must be an absolute path", v)
		}
		c.BackupDir = v
	}
	if v := strings.TrimSpace(os.Getenv("KYDNS_BACKUP_KEEP")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return fmt.Errorf("KYDNS_BACKUP_KEEP: %q must be a positive integer", v)
		}
		c.BackupKeep = n
	}
	if v := strings.TrimSpace(os.Getenv("KYDNS_BACKUP_ALLOW_PRIVATE_RECOVERY")); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("KYDNS_BACKUP_ALLOW_PRIVATE_RECOVERY: %q must be true or false", v)
		}
		c.BackupAllowPrivateRecovery = b
	}
	return nil
}
```

Also make the early-return path (`!ok || raw == ""`) call `c.applyBackupDestinationEnv()` instead of `return nil`, so the destination vars apply when the interval is unset. Add `path/filepath` and `strconv` imports.

- [ ] **Step 4: Run tests**

Run: `go test -race ./internal/config`
Expected: PASS, including the existing example-contract test.

- [ ] **Step 5: Commit**

```bash
git switch -c feat/backup-suite-spec
git add internal/config
git commit -m "feat(config): read KYDNS_BACKUP_DIR, _KEEP and _ALLOW_PRIVATE_RECOVERY

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 3: Compose: pass backup env through, add the LAN DNS override file

**Files:**
- Modify: `docker-compose.yml` (add an `environment:` block to the `kydns` service; no `dns:` entry)
- Create: `docker-compose.lan-dns.yml`
- Modify: `.env.example` (document the four backup variables and `KYDNS_DNS`)

Spec row 8. The `dns:` entry lives in its own file because it replaces the host's resolvers for every lookup the container makes.

- [ ] **Step 1: Add the environment block**

In `docker-compose.yml`, under `services.kydns`, after `security_opt`, add:

```yaml
    environment:
      # Backups. The schedule is set in the admin UI once Phase B lands; this is
      # only its default. A local backup directory needs a volume mounted at the
      # same path. See README "Backups".
      KYDNS_BACKUP_DEPOSIT_INTERVAL: ${KYDNS_BACKUP_DEPOSIT_INTERVAL:-24h}
      KYDNS_BACKUP_DIR: ${KYDNS_BACKUP_DIR:-}
      KYDNS_BACKUP_KEEP: ${KYDNS_BACKUP_KEEP:-7}
      KYDNS_BACKUP_ALLOW_PRIVATE_RECOVERY: ${KYDNS_BACKUP_ALLOW_PRIVATE_RECOVERY:-false}
```

- [ ] **Step 2: Create the override file**

`docker-compose.lan-dns.yml`:

```yaml
# Optional override: send the container's DNS lookups to your LAN's resolver, so names that
# exist only there (a KyRecovery behind your own proxy) resolve inside the container. This
# replaces the host's resolvers for every lookup this container makes, which is why it lives
# in its own file instead of a default. KyDNS is itself a resolver; do not point this at the
# KyDNS container's own address.
#
#   KYDNS_DNS=192.168.1.1 docker compose -f docker-compose.yml -f docker-compose.lan-dns.yml up -d
services:
  kydns:
    dns:
      - ${KYDNS_DNS:?set KYDNS_DNS to your LAN DNS server}
```

- [ ] **Step 3: Document in .env.example**

Append:

```sh
# Backups. Optional. The schedule default; the admin UI setting wins once set.
# KYDNS_BACKUP_DEPOSIT_INTERVAL=24h
# Local sealed copies: absolute path inside the container, mounted as a volume.
# KYDNS_BACKUP_DIR=/var/backups/kydns
# KYDNS_BACKUP_KEEP=7
# KyRecovery on your own LAN behind a TLS proxy. HTTPS is still required.
# KYDNS_BACKUP_ALLOW_PRIVATE_RECOVERY=false
# LAN resolver for the container, used only with docker-compose.lan-dns.yml on
# the command line. A value here alone does nothing.
# KYDNS_DNS=192.168.1.1
```

- [ ] **Step 4: Prove compose parses both forms**

Run (needs a `.env` with the required vars; use a scratch copy):

```bash
cp .env.example /tmp/kydns-compose.env
printf 'KYDNS_IP=192.168.1.53\nKYDNS_PARENT_IF=eth0\nKYDNS_SUBNET=192.168.1.0/24\nKYDNS_GATEWAY=192.168.1.1\n' >> /tmp/kydns-compose.env
docker compose --env-file /tmp/kydns-compose.env -f docker-compose.yml config | grep -A4 'environment:'
KYDNS_DNS=192.168.1.1 docker compose --env-file /tmp/kydns-compose.env -f docker-compose.yml -f docker-compose.lan-dns.yml config | grep -A1 'dns:'
docker compose --env-file /tmp/kydns-compose.env -f docker-compose.yml -f docker-compose.lan-dns.yml config 2>&1 | grep -c 'set KYDNS_DNS'
```

Expected: the four backup variables with their defaults; `dns: - 192.168.1.1`; and `1` (the override without `KYDNS_DNS` fails with the message).

- [ ] **Step 5: Commit**

```bash
git add docker-compose.yml docker-compose.lan-dns.yml .env.example
git commit -m "feat(compose): pass backup env through and add the LAN DNS override

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 4: Restore runbook, proven in a scratch run

**Files:**
- Create: `docs/RESTORE.md`
- Create: `scripts/restore-drill.sh` (the proof, re-runnable)
- Modify: `AGENTS.md` (add `docs/RESTORE.md` to the DOX index), `README.md` (link it)

Spec row 12. Written against `kydns restore --capsule PATH --out DIR` as it exists today. Task 8 replaces the implementation with the library's `Restore` but keeps the flags, so this document stays true. Template: `kysignon-server/docs/RESTORE.md`; copy structure, not text.

- [ ] **Step 1: Write the proof script first**

`scripts/restore-drill.sh` builds the binary, generates a fresh 2-of-3 key with a throwaway Go program, seals a capsule from a scratch data dir, and runs `restore` against it in every mode the runbook names. It exits non-zero on any unexpected outcome.

```bash
#!/usr/bin/env bash
# Proves docs/RESTORE.md Step 1 against a capsule sealed to a fresh 2-of-3 key.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$root"
go build -o "$work/kydns" ./cmd/kydns

# A throwaway key and a capsule sealed to it. The helper prints three share
# lines then the capsule path; it exists only inside this script.
mkdir -p "$work/gen"
cat > "$work/gen/main.go" <<'EOF'
package main

import (
	"fmt"
	"os"

	"github.com/Busness-app/ky-primitives/capsule"
	"github.com/Busness-app/ky-primitives/recoverykey"
)

func main() {
	priv, err := recoverykey.Generate()
	if err != nil {
		panic(err)
	}
	shares, err := recoverykey.Split(priv, 2, 3)
	if err != nil {
		panic(err)
	}
	for _, s := range shares {
		fmt.Fprintln(os.Stderr, s.String())
	}
	files := []capsule.File{
		{Path: "data/kydns.db", Content: []byte("not a real db; restore does not open it"), Mode: 0600},
		{Path: "data/backup_key", Content: make([]byte, 32), Mode: 0600},
		{Path: "config/kydns.yaml", Content: []byte("data_dir: /var/lib/kydns\n"), Mode: 0600},
	}
	raw, _, err := capsule.Seal("KyDNS", "drill", files, map[string]any{}, map[string]any{}, 2, 3, priv.Public())
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(os.Args[1], raw, 0600); err != nil {
		panic(err)
	}
}
EOF
go run "$work/gen/main.go" "$work/kydns.kycap" 2> "$work/shares.txt"
[ "$(wc -l < "$work/shares.txt")" -eq 3 ]

# Happy path: two shares on stdin.
mkdir -m 700 "$work/out"
head -2 "$work/shares.txt" | "$work/kydns" restore --capsule "$work/kydns.kycap" --out "$work/out"
test -f "$work/out/data/kydns.db" && test -f "$work/out/data/backup_key" && test -f "$work/out/config/kydns.yaml"
[ "$(stat -c %a "$work/out/data/backup_key")" = "600" ]

# One share: refused.
mkdir -m 700 "$work/one"
if head -1 "$work/shares.txt" | "$work/kydns" restore --capsule "$work/kydns.kycap" --out "$work/one"; then
	echo "one share was accepted" >&2; exit 1
fi

# Non-empty target: refused, and the existing file survives.
echo keep > "$work/out/marker"
if head -2 "$work/shares.txt" | "$work/kydns" restore --capsule "$work/kydns.kycap" --out "$work/out"; then
	echo "non-empty target was accepted" >&2; exit 1
fi
[ "$(cat "$work/out/marker")" = "keep" ]

# Shares never on argv: the command must not accept them there.
share=$(head -1 "$work/shares.txt")
mkdir -m 700 "$work/argv"
if "$work/kydns" restore --capsule "$work/kydns.kycap" --out "$work/argv" "$share" </dev/null; then
	echo "a share on argv was accepted" >&2; exit 1
fi
echo "restore drill: all checks passed"
```

Check the real names in `ky-primitives/recoverykey` before running: the split function and the share `String()` method must match what the package exports at v0.4.1 (`go doc github.com/Busness-app/ky-primitives/recoverykey`). If the names differ, fix the script, not the library.

- [ ] **Step 2: Run the script; fix what it exposes**

Run: `chmod +x scripts/restore-drill.sh && scripts/restore-drill.sh`
Expected: `restore drill: all checks passed`.

Known gap to expect: `cmd/kydns/main.go:93-131` does not check that `--out` is empty, and does not check the unverified manifest's service name before `Combine`. If the non-empty-target check fails, add to the `restore` case before `os.ReadFile`:

```go
		if entries, err := os.ReadDir(*out); err == nil && len(entries) > 0 {
			fmt.Fprintln(os.Stderr, "kydns: restore directory must be empty")
			return 1
		}
```

and a test in `cmd/kydns/main_test.go` that a directory with one file makes `run([]string{"restore", "--capsule", p, "--out", dir}, &buf)` return 1 before reading stdin. `capsule.Open` also refuses to overwrite; the pre-check exists so the operator learns before typing shares.

- [ ] **Step 3: Write docs/RESTORE.md**

Structure and required content (adapt every path and key to KyDNS; do not paste KySignOn text):

1. **Title and the three-party table**: capsule (KyRecovery, `KYDNS_BACKUP_DIR`, or a downloaded copy), k custodian cards, a machine.
2. **What a capsule holds**: table of `data/kydns.db` (services, records, views, blacklists, settings, admin hash, API tokens, DHCP leases, local settings, audit), `data/backup_key` (32 bytes; the sealed KyRecovery token in the database opens only with it), `data/node_key` (replica identity; present only when this node has joined or hosted replication), `config/kydns.yaml` (data_dir, dns.listen, admin.listen; reference only). State plainly: the restored directory is the live `data_dir` in the clear.
3. **Before you start**: pick the capsule (KyRecovery dashboard → Capsules → newest `KyDNS`, note id/created_at/digest; or `KyDNS.<id>.kycap` from the local directory), gather k custodians (share lines begin `ky2-`; they type their own), prepare an empty mode-700 directory.
4. **Step 1: open the capsule**. Binary form:
   ```bash
   kydns restore --capsule KyDNS.XXXXXXXX.kycap --out ./restored
   ```
   Docker form with `docker compose run --rm --no-deps --user "$(id -u):$(id -g)" -v "$PWD/cap.kycap:/cap.kycap:ro" -v "$PWD/restored:/restored" kydns restore --capsule /cap.kycap --out /restored`. Custodians type one share per line, then Ctrl-D. Failure modes with the exact message each produces (copy from the script's run): one share, wrong service, non-empty directory.
5. **Step 2: check what came out**: `ls -la restored/data restored/config`; `sqlite3 restored/data/kydns.db 'PRAGMA integrity_check; SELECT count(*) FROM services;'`; compare capsule id from the tool's printed manifest with the KyRecovery record.
6. **Step 3: put it in service**. Empty-volume gate first: `docker compose run --rm --no-deps --entrypoint sh kydns -c 'ls -A /var/lib/kydns'` must print nothing. If it does not, copy the old volume out first: `mkdir -m 700 old-data && docker compose run --rm --no-deps --user root --entrypoint sh -v "$PWD/old-data:/old" kydns -c 'cp -a /var/lib/kydns/. /old/ && ls -A /old | wc -l'`, compare the count, then `docker compose down -v`. Explain the hazard: a leftover `kydns.db-wal` replays into the restored database. Then copy `restored/data/.` into the fresh volume the same way (as root, since the volume is root-owned and caps are dropped), `docker compose up -d`, and `docker compose logs kydns | head`.
7. **Step 4: prove it**: `dig @$KYDNS_IP <a known private name>`; log in to the admin UI with the old password; Settings shows the pinned key ID; if the backup was paired, Back up now works without re-pairing; if it says the key is missing, `data/recovery.pub` did not come across, and re-pairing is accepted only to the same key. Replica: a restored primary with `node_key` keeps its identity, replicas reconnect; a standalone node has no `node_key` and nothing to prove.
8. **Step 5: decide what to trust**. Everything is as of `created_at`. Re-apply later changes from the old audit table (`SELECT * FROM audit_events WHERE created_at > ?` on `old-data/kydns.db`). Sessions: KyDNS sessions are server-side; revoke by rotating (below). API tokens: regenerate each in Settings. Rotation after a suspected compromise: `backup_key` can be rotated only by unpairing and pairing again (the sealed token opens only under the old key), and it must not be deleted while paired; `node_key` is rotated by removing this node from replication and joining again. Name no key as "never rotate": KyDNS has no database encryption key. Say that explicitly so nobody hunts for one.
9. **Afterwards**: delete `restored/` and `old-data/` (`sudo rm -rf` for the root-owned copy); cards unchanged; an exposed card is a suite-wide ceremony; take a fresh backup.
10. **Drill it**: `scripts/restore-drill.sh` proves the format; a quarterly run with real cards proves the cards. Link the in-app drill.

Never print a key or share in the document beyond the `ky2-` prefix.

- [ ] **Step 4: Cross-check every command in the runbook against the script and the CLI**

Run: `grep -o 'kydns restore[^`]*' docs/RESTORE.md | sort -u` and confirm each matches the usage line at `cmd/kydns/main.go:99`. Run `scripts/restore-drill.sh` once more.

- [ ] **Step 5: Index it**

`AGENTS.md`: under the docs list near line 58 add `- docs/RESTORE.md — restore runbook; scripts/restore-drill.sh proves Step 1.` `README.md` line 13 paragraph: append `Restoring is [documented step by step](docs/RESTORE.md).`

- [ ] **Step 6: Commit**

```bash
git add docs/RESTORE.md scripts/restore-drill.sh AGENTS.md README.md cmd/kydns
git commit -m "docs(backup): restore runbook with a scripted proof

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 5: README and SECURITY: why TLS matters, pin by hand, every env var

**Files:**
- Modify: `README.md` (lines 10-13 paragraph becomes a "Backups" section), `SECURITY.md:165-169`

Spec row 13, the parts that do not depend on Phase B. Row 14 (delete the stale spec copy) is already done: `git ls-files | grep zero_code` is empty.

- [ ] **Step 1: Replace the README paragraph with a section**

Replace `README.md:10-13` with a pointer sentence and add a `## Backups` section after the Example section:

```markdown
## Backups

Backups are sealed to the suite recovery key and this server never holds what opens them.
The key arrives by pairing with KyRecovery, or (Phase B) is pasted from the ceremony page
for a server with no KyRecovery. Every capsule is sealed to it and goes to each configured
destination: KyRecovery when paired, and `KYDNS_BACKUP_DIR` when set, as
`KyDNS.<capsule-id>.kycap` at mode 0600. The newest `KYDNS_BACKUP_KEEP` (default 7) with
that prefix are kept; other files in the directory are never touched.

`KYDNS_BACKUP_DEPOSIT_INTERVAL` (default `24h`, 15 minute floor, `0` disables) is the
schedule default. Custodian cards come from the KyRecovery ceremony; a restore needs k of
them typed on stdin, see [docs/RESTORE.md](docs/RESTORE.md).

**KyRecovery must be reached over HTTPS, and by default at a public address.** TLS is not
for the capsule, which is already sealed. It protects the public key that arrives at
pairing (trust on first use), the deposit token, and the receipts. For a KyRecovery on your
own network behind a TLS proxy, set `KYDNS_BACKUP_ALLOW_PRIVATE_RECOVERY=true`; HTTPS is
still required and loopback stays refused. Whatever the wire, compare the key fingerprint
Settings shows with the one in the KyRecovery dashboard; a swapped key then fails at
pairing instead of at restore. In Docker, names that exist only on your LAN need
`docker-compose.lan-dns.yml` with `KYDNS_DNS` on the command line.
```

Keep the `(Phase B)` marker only until Task 7 lands; Task 9 removes it.

- [ ] **Step 2: Extend SECURITY.md**

After the existing KyRecovery paragraph at line 165, add one paragraph: private and CGNAT targets are refused unless `KYDNS_BACKUP_ALLOW_PRIVATE_RECOVERY` is set, which is logged at startup and on the pairing audit row; loopback, link-local, multicast, unspecified and reserved ranges are refused regardless; plain HTTP is never accepted; the operator compares fingerprints because TLS protects the wire, not the capsule.

- [ ] **Step 3: Check every env var named in docs exists in config**

Run: `grep -oh 'KYDNS_BACKUP_[A-Z_]*' README.md SECURITY.md .env.example docker-compose.yml | sort -u` and `grep -oh 'KYDNS_BACKUP_[A-Z_]*' internal/config/config.go | sort -u`
Expected: identical lists.

- [ ] **Step 4: Commit and open the Phase A PR**

```bash
git add README.md SECURITY.md
git commit -m "docs(backup): explain TLS, fingerprints and every backup env var

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

Run the full gate (`gofmt -l . ; go vet ./... ; go test -race ./... ; git diff --check`), then use the `pull-request` skill: title `feat(backup): config, compose and runbook for the suite backup spec`. Post the PR URL to MySlop folder `kydns-kyrecovery-deposit` (see Hand-off below).

---

## Phase B: on `ky-primitives/recoveryclient` v0.5.0

**Gate: satisfied.** `v0.5.0` was tagged on 2026-09-04 and resolves through the module proxy (`go get github.com/Busness-app/ky-primitives@v0.5.0` succeeds). It points at 533a053, the commit the surface block below was read from, so the block is the tag's API, verified with `go doc` on the tagged module. Phase A and Phase B can run back to back on one branch; keep them as separate PRs (Task 5 opens the first) so the review of the library adoption is not mixed with config and docs.

**Before Task 6:** run `go doc github.com/Busness-app/ky-primitives/recoveryclient` after bumping and diff against the surface below, which was read from master at 533a053 (not from the design post). Where a name differs, follow the library and note it in the commit body. Where a behaviour differs, stop and post to the board; do not paper over it in KyDNS.

Library surface at v0.5.0:

```go
package recoveryclient // import "github.com/Busness-app/ky-primitives/recoveryclient"

// Settings keys the package writes: kyrecovery_key_id, kyrecovery_threshold,
// kyrecovery_total_shares, kyrecovery_url, kyrecovery_token_enc,
// kyrecovery_last_deposit, backup_interval_sec, backup_last_attempt.
type Settings interface { Get(key string) (string, error); Set(key, value string) error; Delete(key string) error }
var ErrNotFound error

type Sealer interface { Seal(plain []byte) (string, error); Open(sealed string) ([]byte, error) }
func NewAESGCMSealer(key []byte, label string) (Sealer, error)   // HKDF-SHA256 per label; key >= 32 bytes

type RecoveryKey struct { Public recoverykey.PublicKey; Threshold, TotalShares int }
func RecoveryKeyPath(dataDir string) string                        // <dataDir>/recovery.pub
func StoreRecoveryKey(dataDir string, settings Settings, k RecoveryKey) error   // write-once; ErrKeyMismatch
func LoadRecoveryKey(dataDir string, settings Settings) (RecoveryKey, error)    // ErrNotPaired, ErrKeyMismatch
func ParsePinRequest(publicKeyB64 string, threshold, total int) (RecoveryKey, error)
var ErrNotPaired, ErrKeyMismatch error

type Pairing struct { URL, Token string; Key RecoveryKey }
func StorePairing(settings Settings, sealer Sealer, serverURL, token string) error
func LoadPairing(dataDir string, settings Settings, sealer Sealer) (Pairing, error)  // ErrKeyPinMissing
func HasPairing(settings Settings) bool
func ClearPairing(settings Settings) error                          // rows only; ErrNotPaired when none
func LastDeposit(settings Settings) (Receipt, bool, error)
var ErrKeyPinMissing error

type Options struct{ AllowPrivate bool }
type Client struct{ ... }
func NewClient(o Options) *Client
func ValidateURL(raw string, allowPrivate bool) error
type PairingResult struct { APIToken string; Key RecoveryKey }
func (c *Client) ClaimPairing(ctx context.Context, serverURL, pairingCode, serviceName, appName string) (PairingResult, error)
type Receipt struct { CapsuleID, Digest string; SizeBytes int64; DepositedAt time.Time }
func (c *Client) Deposit(ctx context.Context, serverURL, apiToken string, container []byte) (Receipt, error)
type Depositor interface { Deposit(ctx context.Context, serverURL, apiToken string, container []byte) (Receipt, error) }
var ErrRemote error

type LocalCopy struct { Name string; SizeBytes int64; CreatedAt time.Time }
func WriteLocalCopy(dir, appName, capsuleID string, raw []byte, keep int) (string, error)  // <escaped-app>.<id>.kycap
func ListLocalCopies(dir, appName string) ([]LocalCopy, error)
var ErrBadKeep error

const MinInterval = 15 * time.Minute; const MaxInterval = 366 * 24 * time.Hour
var ErrBadInterval error
func Interval(defaultInterval time.Duration, settings Settings) (time.Duration, error)
func SetInterval(settings Settings, sec int64) error
func NextRun(defaultInterval time.Duration, settings Settings) (time.Time, bool, error)

type File struct { Path string; Data []byte; Mode int64 }
type Payload struct { ServiceName, AppVersion string; Files []File; Dependencies, VerificationRecipe map[string]any }
func Seal(p Payload, key RecoveryKey) ([]byte, capsule.Manifest, error)
const MaxCapsuleFileBytes, MaxCapsuleTotalBytes int; var TooLargeMessage string
func FilenameSafe(s string) string
func AuditSafe(s string) string                                     // printable, 200 chars

type RunConfig struct { DataDir, AppName, AppVersion, BackupDir string; Keep int; Sealer Sealer }
type Result struct { Manifest capsule.Manifest; SizeBytes int; LocalPath, LocalError string; Receipt *Receipt }
func Run(ctx context.Context, cfg RunConfig, settings Settings, collect func() (Payload, error), client Depositor) (Result, error)
func Outcome(res Result, err error) (action, outcome string, details map[string]any)  // action is always "admin.backup_run"
var ErrNoDestination, ErrInProgress, ErrReceiptUnrecorded error

type Check struct { Name string; Passed bool; Message string }
type DrillResult struct { Passed bool; Checks []Check; ErrorMessage string; DurationMs int64; SizeBytes int }
func Drill(ctx context.Context, scratchRoot string, payload Payload, checks func(dir string) []Check) (*DrillResult, error)
var ErrNoScratchRoot error                                          // scratchRoot must be inside the data dir

func ReadShares(r io.Reader) ([]string, error)
func Restore(capsulePath, targetDir, expectService string, shareStrings []string, stdout io.Writer) error

func SQLiteSnapshot(ctx context.Context, db *sql.DB, destPath string) error   // VACUUM INTO; destPath must not exist; 0600

package guardtest // import ".../recoveryclient/guardtest"
const MinFiles = 10
func NoDecryptOutside(t testing.TB, repoRoot string, allowed map[string][]string)
// forbids capsule.Open, recoverykey.Combine, recoverykey.FromSeed, recoveryclient.Restore outside allowed
```

Behaviours that matter for the adapter: `Run` refuses a payload whose `ServiceName` differs from `RunConfig.AppName` before uploading; `Outcome` fixes the audit action to `admin.backup_run` and returns bounded details as a map; `Drill` needs a scratch root under the data directory and no longer takes the pinned key; local copies use a dot delimiter, so KyDNS's are `KyDNS.<capsule-id>.kycap`; the token row is `kyrecovery_token_enc`, distinct from #27's `kyrecovery_token`, so an old plaintext-format row is never mistaken for ciphertext.

---

### Task 6: Replace the hand-rolled backup core with the library

**Files:**
- Modify: `go.mod`, `go.sum`
- Rewrite: `internal/backup/backup.go` (keep: `Collect`, `Seal`, the `Settings`/`Snapshotter` adapters, `Status`; delete: token sealing, key pin, pairing storage, `Deposit`, `Drill` internals, error vars now in the library)
- Delete: `internal/backup/client.go`
- Rewrite: `internal/backup/backup_test.go`
- Create: `internal/backup/AGENTS.md`

**Interfaces:**
- Consumes: the library surface above; `store.Store` methods `GetLocalSetting`, `SetLocalSetting`, `DeleteLocalSetting`, `SnapshotTo`, `RecordAudit`; `store.ErrNotFound`.
- Produces (used by Tasks 7, 8, 9):

```go
package backup

const ServiceName = "KyDNS"

// Service is everything a route, the scheduler and the CLI need. Built once in app.Serve.
type Service struct {
	Cfg     *config.Config
	Store   *store.Store
	Client  *recoveryclient.Client
	Version string
}

func New(cfg *config.Config, st *store.Store, version string) (*Service, error)  // opens/creates backup_key, builds sealer and client
func (s *Service) Settings() recoveryclient.Settings                              // adapter over Store
func (s *Service) Sealer() recoveryclient.Sealer
func (s *Service) Collect() (recoveryclient.Payload, error)                       // today's Collect, returning a Payload
func (s *Service) Run(ctx context.Context) (recoveryclient.Result, error)            // recoveryclient.Run with RunConfig from cfg
func (s *Service) Export() ([]byte, capsule.Manifest, error)                     // seal to the pinned key without delivering
func (s *Service) Drill(ctx context.Context) (*recoveryclient.DrillResult, error) // recoveryclient.Drill under DataDir with KyDNS checks
func (s *Service) Pair(ctx context.Context, url, code string) (recoveryclient.RecoveryKey, error)
func (s *Service) PinKey(publicKeyB64 string, k, n int) (recoveryclient.RecoveryKey, error)
func (s *Service) Unpair() error
func (s *Service) SetSchedule(sec int64) (time.Duration, error)                  // stores, then reads back what is stored
func (s *Service) Status() (Status, error)

type Status struct {
	KeyPinned     bool                    `json:"key_pinned"`
	RecoveryKeyID string                  `json:"recovery_key_id,omitempty"`
	Threshold     int                     `json:"threshold,omitempty"`
	TotalShares   int                     `json:"total_shares,omitempty"`
	KeyPinMissing bool                    `json:"key_pin_missing"`
	Paired        bool                    `json:"paired"`
	RecoveryURL   string                  `json:"recovery_url,omitempty"`
	AllowPrivate  bool                    `json:"allow_private_recovery"`
	LastDeposit   *recoveryclient.Receipt     `json:"last_deposit,omitempty"`
	LocalDir      string                  `json:"local_dir,omitempty"`
	LocalKeep     int                     `json:"local_keep,omitempty"`
	LocalCopies   []recoveryclient.LocalCopy  `json:"local_copies"`
	IntervalSec   int64                   `json:"interval_sec"`
	NextRun       *time.Time              `json:"next_run,omitempty"`
	HasDestination bool                   `json:"has_destination"`
}
```

Decision recorded here: the sealed-token format changes from #27's hand-rolled AES-GCM to the library sealer. No KyDNS instance has paired against a live KyRecovery (board post 164), so there is nothing to migrate. If `LoadPairing` fails to open a token, `Status.KeyPinMissing` is false and `Paired` is true, and the screen's pairing panel says "re-pair"; do not add a fallback decoder.

- [ ] **Step 1: Bump the module**

```bash
go get github.com/Busness-app/ky-primitives@v0.5.0
go mod tidy
go doc github.com/Busness-app/ky-primitives/recoveryclient | head -80
```

Compare with the surface above; record renames.

- [ ] **Step 2: Write the failing tests**

Replace `internal/backup/backup_test.go`:

```go
package backup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Busness-app/ky-primitives/capsule"
	"github.com/Busness-app/ky-primitives/recoveryclient"
	"github.com/Busness-app/ky-primitives/recoverykey"
	"github.com/Busness-app/kydns-server/internal/config"
	"github.com/Busness-app/kydns-server/internal/store"
)

func testService(t *testing.T, tweak func(*config.Config)) *Service {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "kydns.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	cfg := &config.Config{DataDir: dir, BackupKeep: 7, DNS: config.DNSConfig{Listen: ":53"}, Admin: config.AdminConfig{Listen: "127.0.0.1:8053"}}
	if tweak != nil {
		tweak(cfg)
	}
	s, err := New(cfg, st, "test")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func pinFresh(t *testing.T, s *Service) recoverykey.PrivateKey {
	t.Helper()
	priv, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.StdEncoding.EncodeToString(priv.Public().Bytes())
	if _, err := s.PinKey(b64, 2, 3); err != nil {
		t.Fatal(err)
	}
	return priv
}

func TestPinByHandIsWriteOnce(t *testing.T) {
	s := testService(t, nil)
	pinFresh(t, s)
	other, _ := recoverykey.Generate()
	_, err := s.PinKey(base64.StdEncoding.EncodeToString(other.Public().Bytes()), 2, 3)
	if !errors.Is(err, recoveryclient.ErrKeyMismatch) {
		t.Fatalf("second pin error = %v, want ErrKeyMismatch", err)
	}
}

func TestPinnedKeyWithNoDestinationIsNoDestination(t *testing.T) {
	s := testService(t, nil)
	pinFresh(t, s)
	if _, err := s.Run(context.Background()); !errors.Is(err, recoveryclient.ErrNoDestination) {
		t.Fatalf("Run error = %v, want ErrNoDestination", err)
	}
}

func TestRunWritesALocalCopyOnlyKeyOpens(t *testing.T) {
	dir := t.TempDir()
	s := testService(t, func(c *config.Config) { c.BackupDir = dir; c.BackupKeep = 1 })
	priv := pinFresh(t, s)
	res, err := s.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(filepath.Base(res.LocalPath), "KyDNS.") {
		t.Fatalf("local path %q lacks the KyDNS. prefix", res.LocalPath)
	}
	info, _ := os.Stat(res.LocalPath)
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode = %o", info.Mode().Perm())
	}
	raw, _ := os.ReadFile(res.LocalPath)
	if _, _, err := capsule.Open(raw, priv, ""); err != nil {
		t.Fatal(err)
	}
	wrong, _ := recoverykey.Generate()
	if _, _, err := capsule.Open(raw, wrong, ""); !errors.Is(err, capsule.ErrWrongRecoveryKey) {
		t.Fatalf("wrong key error = %v", err)
	}
	// A second run prunes to keep=1 but leaves a foreign file alone.
	foreign := filepath.Join(dir, "Other-x.kycap")
	os.WriteFile(foreign, []byte("x"), 0600)
	if _, err := s.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	copies, _ := recoveryclient.ListLocalCopies(dir, ServiceName)
	if len(copies) != 1 {
		t.Fatalf("copies = %d, want 1", len(copies))
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Fatal("foreign capsule was pruned")
	}
}

func TestCapsuleCarriesEveryRequiredMember(t *testing.T) {
	s := testService(t, nil)
	priv := pinFresh(t, s)
	raw, _, err := s.Export()
	if err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	if _, _, err := capsule.Open(raw, priv, out); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"data/kydns.db", "data/backup_key", "config/kydns.yaml"} {
		if _, err := os.Stat(filepath.Join(out, p)); err != nil {
			t.Errorf("missing %s", p)
		}
	}
}

func TestScheduleIsBoundedInSeconds(t *testing.T) {
	s := testService(t, nil)
	for _, sec := range []int64{-1, 1, 14 * 60, 366*24*3600 + 1, 1 << 55} {
		if _, err := s.SetSchedule(sec); err == nil {
			t.Errorf("SetSchedule(%d) accepted", sec)
		}
	}
	got, err := s.SetSchedule(0)
	if err != nil || got != 0 {
		t.Fatalf("SetSchedule(0) = %v, %v", got, err)
	}
	got, err = s.SetSchedule(3600)
	if err != nil || got != time.Hour {
		t.Fatalf("SetSchedule(3600) = %v, %v", got, err)
	}
}

func TestUnpairKeepsThePin(t *testing.T) {
	s := testService(t, nil)
	pinFresh(t, s)
	if err := s.Unpair(); !errors.Is(err, recoveryclient.ErrNotPaired) {
		t.Fatalf("Unpair when never paired = %v", err)
	}
	// Plant a pairing record directly, as StorePairing would.
	if err := recoveryclient.StorePairing(s.Settings(), s.Sealer(), "https://recovery.example", "tok"); err != nil {
		t.Fatal(err)
	}
	if err := s.Unpair(); err != nil {
		t.Fatal(err)
	}
	st, _ := s.Status()
	if st.Paired || !st.KeyPinned {
		t.Fatalf("after unpair: %+v", st)
	}
}

func TestTokenNeverStoredInTheClear(t *testing.T) {
	s := testService(t, nil)
	pinFresh(t, s)
	if err := recoveryclient.StorePairing(s.Settings(), s.Sealer(), "https://recovery.example", "plain-secret-token"); err != nil {
		t.Fatal(err)
	}
	rows := dumpLocalSettings(t, s.Store)
	if strings.Contains(rows, "plain-secret-token") {
		t.Fatal("token stored in plaintext")
	}
}

func TestDrillRunsKyDNSChecks(t *testing.T) {
	s := testService(t, nil)
	res, err := s.Drill(context.Background())
	if err != nil || res == nil || !res.Passed {
		t.Fatalf("Drill = %+v, %v", res, err)
	}
	names := map[string]bool{}
	for _, c := range res.Checks {
		names[c.Name] = c.Passed
	}
	for _, want := range []string{"sqlite integrity", "required files"} {
		if !names[want] {
			t.Errorf("check %q missing or failed", want)
		}
	}
}
```

Add `dumpLocalSettings` as a small helper that opens the SQLite file read-only and concatenates every `value` from `local_settings`. Add `encoding/base64` and `time` imports.

- [ ] **Step 3: Run to verify failure**

Run: `go test ./internal/backup 2>&1 | head`
Expected: compile errors for `New`, `Service`, etc.

- [ ] **Step 4: Rewrite backup.go**

```go
// Package backup is KyDNS's adapter over ky-primitives/recoveryclient: what to seal, the
// KyDNS drill checks, and one Service the routes, scheduler and CLI share. Pairing,
// key pinning, delivery, schedule and restore live in the library.
package backup

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/Busness-app/ky-primitives/capsule"
	"github.com/Busness-app/ky-primitives/keyfile"
	"github.com/Busness-app/ky-primitives/recoveryclient"
	"github.com/Busness-app/kydns-server/internal/config"
	"github.com/Busness-app/kydns-server/internal/store"
	"gopkg.in/yaml.v3"
)

const (
	ServiceName = "KyDNS"
	keyFile     = "backup_key"
	tokenLabel  = "KyDNS:kyrecovery_token"
)

type Service struct {
	Cfg     *config.Config
	Store   *store.Store
	Client  *recoveryclient.Client
	Version string
	sealer  recoveryclient.Sealer
}

func New(cfg *config.Config, st *store.Store, version string) (*Service, error) {
	key, err := keyfile.LoadOrCreate(filepath.Join(cfg.DataDir, keyFile), 32)
	if err != nil {
		return nil, err
	}
	sealer, err := recoveryclient.NewAESGCMSealer(key, tokenLabel)
	if err != nil {
		return nil, err
	}
	return &Service{Cfg: cfg, Store: st, Version: version,
		Client: recoveryclient.NewClient(recoveryclient.Options{AllowPrivate: cfg.BackupAllowPrivateRecovery}),
		sealer: sealer}, nil
}

func (s *Service) Sealer() recoveryclient.Sealer { return s.sealer }

// settingsAdapter maps the store's node-local settings onto the library's interface.
type settingsAdapter struct{ st *store.Store }

func (a settingsAdapter) Get(k string) (string, error) {
	v, err := a.st.GetLocalSetting(k)
	if errors.Is(err, store.ErrNotFound) {
		return "", recoveryclient.ErrNotFound
	}
	return v, err
}
func (a settingsAdapter) Set(k, v string) error { return a.st.SetLocalSetting(k, v) }
func (a settingsAdapter) Delete(k string) error { return a.st.DeleteLocalSetting(k) }

func (s *Service) Settings() recoveryclient.Settings { return settingsAdapter{s.Store} }

func (s *Service) runConfig() recoveryclient.RunConfig {
	return recoveryclient.RunConfig{DataDir: s.Cfg.DataDir, AppName: ServiceName, AppVersion: s.Version,
		BackupDir: s.Cfg.BackupDir, Keep: s.Cfg.BackupKeep, Sealer: s.sealer}
}

// Collect is what a KyDNS capsule carries. Missing required members fail closed.
func (s *Service) Collect() (recoveryclient.Payload, error) {
	tmp, err := os.MkdirTemp(s.Cfg.DataDir, ".backup-*")
	if err != nil {
		return recoveryclient.Payload{}, err
	}
	defer os.RemoveAll(tmp)
	dbPath := filepath.Join(tmp, "kydns.db")
	if err := s.Store.SnapshotTo(dbPath); err != nil {
		return recoveryclient.Payload{}, err
	}
	db, err := os.ReadFile(dbPath)
	if err != nil {
		return recoveryclient.Payload{}, err
	}
	manifest, err := yaml.Marshal(map[string]any{"data_dir": s.Cfg.DataDir,
		"dns": map[string]string{"listen": s.Cfg.DNS.Listen}, "admin": map[string]string{"listen": s.Cfg.Admin.Listen}})
	if err != nil {
		return recoveryclient.Payload{}, err
	}
	backupKey, err := os.ReadFile(filepath.Join(s.Cfg.DataDir, keyFile))
	if err != nil {
		return recoveryclient.Payload{}, fmt.Errorf("required backup member %s: %w", keyFile, err)
	}
	files := []recoveryclient.File{
		{Path: "data/kydns.db", Data: db, Mode: 0600},
		{Path: "data/" + keyFile, Data: backupKey, Mode: 0600},
		{Path: "config/kydns.yaml", Data: manifest, Mode: 0600},
	}
	required := []string{"data/kydns.db", "data/" + keyFile, "config/kydns.yaml"}
	if b, err := os.ReadFile(filepath.Join(s.Cfg.DataDir, "node_key")); err == nil {
		files = append(files, recoveryclient.File{Path: "data/node_key", Data: b, Mode: 0600})
		required = append(required, "data/node_key")
	} else if !errors.Is(err, fs.ErrNotExist) {
		return recoveryclient.Payload{}, err
	}
	return recoveryclient.Payload{ServiceName: ServiceName, AppVersion: s.Version, Files: files,
		Dependencies:       map[string]any{"ports": []string{s.Cfg.DNS.Listen, s.Cfg.Admin.Listen}},
		VerificationRecipe: map[string]any{"check_sqlite_integrity": true, "sqlite_paths": []string{"data/kydns.db"}, "required_files": required},
	}, nil
}

func (s *Service) Run(ctx context.Context) (recoveryclient.Result, error) {
	return recoveryclient.Run(ctx, s.runConfig(), s.Settings(), s.Collect, s.Client)
}

// Export seals to the pinned key and hands the bytes back without delivering them.
func (s *Service) Export() ([]byte, capsule.Manifest, error) {
	key, err := recoveryclient.LoadRecoveryKey(s.Cfg.DataDir, s.Settings())
	if err != nil {
		return nil, capsule.Manifest{}, err
	}
	p, err := s.Collect()
	if err != nil {
		return nil, capsule.Manifest{}, err
	}
	return recoveryclient.Seal(p, key)
}

// Drill scratch space lives under DataDir: the decrypted payload never lands in the
// system temp directory.
func (s *Service) Drill(ctx context.Context) (*recoveryclient.DrillResult, error) {
	p, err := s.Collect()
	if err != nil {
		return nil, err
	}
	return recoveryclient.Drill(ctx, s.Cfg.DataDir, p, func(dir string) []recoveryclient.Check {
		var checks []recoveryclient.Check
		missing := ""
		for _, f := range p.Files {
			if _, err := os.Stat(filepath.Join(dir, f.Path)); err != nil {
				missing = f.Path
			}
		}
		checks = append(checks, recoveryclient.Check{Name: "required files", Passed: missing == "", Message: missing})
		db, err := store.Open(filepath.Join(dir, "data", "kydns.db"))
		if err == nil {
			defer db.Close()
			err = db.IntegrityCheck()
		}
		detail := ""
		if err != nil {
			detail = recoveryclient.AuditSafe(err.Error())
		}
		return append(checks, recoveryclient.Check{Name: "sqlite integrity", Passed: err == nil, Message: detail})
	})
}

func (s *Service) Pair(ctx context.Context, url, code string) (recoveryclient.RecoveryKey, error) {
	res, err := s.Client.ClaimPairing(ctx, url, code, ServiceName, ServiceName)
	if err != nil {
		return recoveryclient.RecoveryKey{}, err
	}
	if err := recoveryclient.StoreRecoveryKey(s.Cfg.DataDir, s.Settings(), res.Key); err != nil {
		return res.Key, err
	}
	return res.Key, recoveryclient.StorePairing(s.Settings(), s.sealer, url, res.APIToken)
}

func (s *Service) PinKey(publicKeyB64 string, k, n int) (recoveryclient.RecoveryKey, error) {
	key, err := recoveryclient.ParsePinRequest(publicKeyB64, k, n)
	if err != nil {
		return recoveryclient.RecoveryKey{}, err
	}
	return key, recoveryclient.StoreRecoveryKey(s.Cfg.DataDir, s.Settings(), key)
}

func (s *Service) Unpair() error { return recoveryclient.ClearPairing(s.Settings()) }

// SetSchedule stores whole seconds and reads the stored value back, so the audit row
// and the response report what the scheduler will actually use.
func (s *Service) SetSchedule(sec int64) (time.Duration, error) {
	if err := recoveryclient.SetInterval(s.Settings(), sec); err != nil {
		return 0, err
	}
	return recoveryclient.Interval(s.Cfg.BackupDepositInterval, s.Settings())
}
```

Then `Status()`:

```go
func (s *Service) Status() (Status, error) {
	st := Status{AllowPrivate: s.Cfg.BackupAllowPrivateRecovery, LocalDir: s.Cfg.BackupDir, LocalKeep: s.Cfg.BackupKeep, LocalCopies: []recoveryclient.LocalCopy{}}
	key, err := recoveryclient.LoadRecoveryKey(s.Cfg.DataDir, s.Settings())
	switch {
	case err == nil:
		st.KeyPinned, st.RecoveryKeyID, st.Threshold, st.TotalShares = true, key.Public.ID(), key.Threshold, key.TotalShares
	case errors.Is(err, recoveryclient.ErrKeyPinMissing), errors.Is(err, recoveryclient.ErrKeyMismatch):
		st.KeyPinned, st.KeyPinMissing = true, true
	case !errors.Is(err, recoveryclient.ErrNotPaired):
		return st, err
	}
	st.Paired = recoveryclient.HasPairing(s.Settings())
	if st.Paired {
		if u, err := s.Settings().Get("kyrecovery_url"); err == nil {
			st.RecoveryURL = u
		}
	}
	if r, ok, err := recoveryclient.LastDeposit(s.Settings()); err != nil {
		return st, err
	} else if ok {
		st.LastDeposit = &r
	}
	if s.Cfg.BackupDir != "" {
		copies, err := recoveryclient.ListLocalCopies(s.Cfg.BackupDir, ServiceName)
		if err != nil {
			return st, err
		}
		st.LocalCopies = copies
	}
	interval, err := recoveryclient.Interval(s.Cfg.BackupDepositInterval, s.Settings())
	if err != nil {
		return st, err
	}
	st.IntervalSec = int64(interval / time.Second)
	if next, on, err := recoveryclient.NextRun(s.Cfg.BackupDepositInterval, s.Settings()); err != nil {
		return st, err
	} else if on {
		st.NextRun = &next
	}
	st.HasDestination = st.Paired || s.Cfg.BackupDir != ""
	return st, nil
}
```

The URL row key `kyrecovery_url` is the one the library documents on its `Settings` interface; it exports no constant for it. Delete `client.go` and the `var (Err...)` block; the error identities now come from the library.

- [ ] **Step 5: Delegate the store snapshot to the library**

`internal/store/backup.go` `SnapshotTo` keeps its signature and absolute-path check, then calls the library instead of running `VACUUM INTO` itself:

```go
func (s *Store) SnapshotTo(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("snapshot path must be absolute")
	}
	return recoveryclient.SQLiteSnapshot(context.Background(), s.db, path)
}
```

The library refuses an existing destination and sets 0600 after the copy. The existing tests `TestSnapshotIncludesCommittedWALData` and `TestSnapshotPathIsBoundNotInterpolated` stay and must still pass; they are the row-in-the-WAL proof the library's README says each product owns. Add one assertion to the WAL test: `info.Mode().Perm() == 0600` on the snapshot file. Update the `AGENTS.md:74` sentence to say `SnapshotTo` delegates to `recoveryclient.SQLiteSnapshot`.

Run: `go test -race ./internal/store`
Expected: PASS.

- [ ] **Step 6: Run the package tests**

Run: `go test -race ./internal/backup`
Expected: PASS. The rest of the module will not compile yet; that is Tasks 7 and 8.

- [ ] **Step 7: Write internal/backup/AGENTS.md**

Sections: Purpose (one paragraph: KyDNS adapter over `ky-primitives/recoveryclient`), Ownership (what to seal, the drill checks, `Service`), Local Contracts (bullets: `ServiceName` is the claimed name and the sealed name; `backup_key` is created at `New` and is a required capsule member; `node_key` is included when present and then required; token sealed under `NewAESGCMSealer(backup_key, "KyDNS:kyrecovery_token")`; every caller records through `recoveryclient.Outcome`; `SetSchedule` reads back; no server code opens a suite-sealed capsule, pinned by the guard test in Task 8), Verification (`go test -race ./internal/backup`), Child DOX Index: None.

- [ ] **Step 8: Commit**

```bash
git add go.mod go.sum internal/backup internal/store AGENTS.md
git commit -m "refactor(backup): adopt ky-primitives/recoveryclient for pairing, delivery and schedule

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

The module does not build as a whole at this commit; the next two tasks fix the callers. Say so in the commit body.

---

### Task 7: API routes on the new Service, with the write gate

**Files:**
- Rewrite: `internal/adminapi/backup.go`
- Modify: `internal/adminapi/api.go:41,109,282-286` (field type, `WithBackupService`, routes)
- Modify: `internal/adminapi/writegate_test.go` (add the new mutating routes to the table used by `TestEveryMutatingRouteIsRefusedOnAReplica`)
- Create: `internal/adminapi/backup_test.go`
- Modify: `internal/app/serve.go:303,311,378-425` (build `backup.Service`, delete `depositLoop`, add `backupLoop`)

**Interfaces:**
- Consumes: `backup.Service` from Task 6.
- Produces routes: existing `POST /api/v1/backup/drill`, `GET .../export-capsule`, `POST .../pair-remote`, `POST .../deposit` (now runs `Run`, kept under its old name for the CLI), `GET .../status`; new `POST .../pin-key` `{public_key, threshold, total_shares}`, `DELETE .../pairing`, `PUT .../schedule` `{interval_sec}`.

Status codes: 412 `ErrNotPaired`/`ErrKeyPinMissing`/`ErrNoDestination` (message names the fix: "pair, pin a key, or set KYDNS_BACKUP_DIR"); 409 `ErrKeyMismatch`/`ErrInProgress`; 400 `ErrBadInterval` and parse errors; 502 `ErrRemote`; 500 otherwise. Responses never carry a token.

- [ ] **Step 1: Write the failing tests**

`internal/adminapi/backup_test.go` (use the package's existing test constructor for an authed API with a real temp store; look at `writegate_test.go` for how a `*store.Store` and token are set up):

```go
func TestBackupStatusRedactsAndReportsNoDestination(t *testing.T) {
	a, tok := backupAPI(t, func(c *config.Config) {})
	pin := pinKeyReq(t)
	rr := do(t, a, tok, "POST", "/api/v1/backup/pin-key", pin)
	if rr.Code != 200 {
		t.Fatalf("pin-key = %d %s", rr.Code, rr.Body)
	}
	rr = do(t, a, tok, "GET", "/api/v1/backup/status", nil)
	var st backup.Status
	json.Unmarshal(rr.Body.Bytes(), &st)
	if !st.KeyPinned || st.HasDestination {
		t.Fatalf("status = %+v", st)
	}
	if strings.Contains(rr.Body.String(), "token") {
		t.Fatal("status body mentions a token")
	}
	rr = do(t, a, tok, "POST", "/api/v1/backup/deposit", nil)
	if rr.Code != 412 || !strings.Contains(rr.Body.String(), "KYDNS_BACKUP_DIR") {
		t.Fatalf("deposit with no destination = %d %s", rr.Code, rr.Body)
	}
}

func TestBackupPinKeyIsWriteOnce(t *testing.T) {
	a, tok := backupAPI(t, nil)
	do(t, a, tok, "POST", "/api/v1/backup/pin-key", pinKeyReq(t))
	if rr := do(t, a, tok, "POST", "/api/v1/backup/pin-key", pinKeyReq(t)); rr.Code != 409 {
		t.Fatalf("second pin = %d", rr.Code)
	}
}

func TestBackupScheduleReadsBack(t *testing.T) {
	a, tok := backupAPI(t, nil)
	for _, body := range []string{`{"interval_sec": 60}`, `{"interval_sec": -5}`, `{"interval_sec": 36028797018963968}`} {
		if rr := do(t, a, tok, "PUT", "/api/v1/backup/schedule", []byte(body)); rr.Code != 400 {
			t.Errorf("%s = %d", body, rr.Code)
		}
	}
	rr := do(t, a, tok, "PUT", "/api/v1/backup/schedule", []byte(`{"interval_sec": 3600}`))
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"interval_sec":3600`) {
		t.Fatalf("schedule = %d %s", rr.Code, rr.Body)
	}
	events := auditRows(t, a)
	if !strings.Contains(events, "backup.schedule") || !strings.Contains(events, "3600") {
		t.Fatalf("audit rows = %s", events)
	}
}

func TestBackupUnpairWhenNeverPairedIs412(t *testing.T) {
	a, tok := backupAPI(t, nil)
	if rr := do(t, a, tok, "DELETE", "/api/v1/backup/pairing", nil); rr.Code != 412 {
		t.Fatalf("unpair = %d", rr.Code)
	}
}

func TestBackupRunWithLocalDirWritesAndAudits(t *testing.T) {
	dir := t.TempDir()
	a, tok := backupAPI(t, func(c *config.Config) { c.BackupDir = dir })
	do(t, a, tok, "POST", "/api/v1/backup/pin-key", pinKeyReq(t))
	rr := do(t, a, tok, "POST", "/api/v1/backup/deposit", nil)
	if rr.Code != 200 {
		t.Fatalf("run = %d %s", rr.Code, rr.Body)
	}
	copies, _ := recoveryclient.ListLocalCopies(dir, backup.ServiceName)
	if len(copies) != 1 {
		t.Fatalf("copies = %d", len(copies))
	}
	if !strings.Contains(auditRows(t, a), "admin.backup_run") {
		t.Fatal("run not audited")
	}
}

func TestBackupExportRefusedWhenAuditFails(t *testing.T) {
	// Close the store's audit path by dropping the table; export must not stream bytes.
	a, tok := backupAPI(t, func(c *config.Config) {})
	do(t, a, tok, "POST", "/api/v1/backup/pin-key", pinKeyReq(t))
	breakAudit(t, a)
	rr := do(t, a, tok, "GET", "/api/v1/backup/export-capsule", nil)
	if rr.Code != 503 || rr.Body.Len() > 512 {
		t.Fatalf("export with broken audit = %d, %d bytes", rr.Code, rr.Body.Len())
	}
}
```

Helpers to write in the same file: `backupAPI(t, tweak)` builds a temp store, a `config.Config` with `DataDir` and `BackupKeep: 7`, `backup.New`, and an `*API` with `WithBackupService`, returning it plus a bearer token; `pinKeyReq(t)` marshals `{"public_key": <base64 of a fresh recoverykey.Generate().Public().Bytes()>, "threshold": 2, "total_shares": 3}`; `do` performs an authed request; `auditRows` selects `action || ' ' || details` from `audit_events`; `breakAudit` executes `DROP TABLE audit_events` on the store's db (expose a test-only hook if the `*sql.DB` is unexported; the store package already has `open(t)` in its tests, so put `breakAudit` behind an exported `store.(*Store).ExecForTest` only if no existing hook fits).

Also add to the route table in `writegate_test.go`: `POST /api/v1/backup/pin-key`, `DELETE /api/v1/backup/pairing`, `PUT /api/v1/backup/schedule`, and confirm `POST /api/v1/backup/deposit`, `pair-remote`, `drill` are already listed. If they are not, add them; the test is the hardening list for row 10.

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/adminapi -run 'TestBackup|TestEveryMutatingRoute' 2>&1 | head`
Expected: compile failure on `backup.Service`.

- [ ] **Step 3: Rewrite adminapi/backup.go**

```go
package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/Busness-app/ky-primitives/recoveryclient"
	"github.com/Busness-app/kydns-server/internal/backup"
	"github.com/Busness-app/kydns-server/internal/store"
)

func (a *API) requireBackup(w http.ResponseWriter) *backup.Service {
	if a.backup == nil {
		writeErr(w, http.StatusServiceUnavailable, "backup_unavailable", "", "backup service is unavailable")
		return nil
	}
	return a.backup
}

func backupAudit(st *store.Store, action, resource, details, ip, outcome string) error {
	return st.RecordAudit(store.AuditEvent{Actor: "admin", Action: action,
		Resource: recoveryclient.AuditSafe(resource), Details: recoveryclient.AuditSafe(details),
		IP: recoveryclient.AuditSafe(ip), Outcome: outcome})
}

func backupStatusCode(err error) (int, string) {
	switch {
	case errors.Is(err, recoveryclient.ErrKeyPinMissing):
		return http.StatusPreconditionFailed, "paired but the recovery public key is missing or does not match the pin; restore recovery.pub or re-pair"
	case errors.Is(err, recoveryclient.ErrNotPaired):
		return http.StatusPreconditionFailed, "no recovery key: pair with KyRecovery or pin the suite key first"
	case errors.Is(err, recoveryclient.ErrNoDestination):
		return http.StatusPreconditionFailed, "nowhere to put a capsule: pair with KyRecovery or set KYDNS_BACKUP_DIR"
	case errors.Is(err, recoveryclient.ErrKeyMismatch):
		return http.StatusConflict, "already pinned to a different recovery key"
	case errors.Is(err, recoveryclient.ErrInProgress):
		return http.StatusConflict, "a backup is already in progress"
	case errors.Is(err, recoveryclient.ErrBadInterval):
		return http.StatusBadRequest, err.Error()
	case errors.Is(err, recoveryclient.ErrRemote):
		return http.StatusBadGateway, recoveryclient.AuditSafe(err.Error())
	default:
		return http.StatusInternalServerError, recoveryclient.AuditSafe(err.Error())
	}
}

func (a *API) backupFail(w http.ResponseWriter, code string, err error) {
	status, msg := backupStatusCode(err)
	writeErr(w, status, code, "", msg)
}
```

Handlers, one per route, each auditing every outcome:

- `backupStatus`: `s.Status()` → 200 JSON.
- `backupPair`: decode `{recovery_url, pairing_code}`; `key, err := s.Pair(r.Context(), url, code)`; audit `backup.paired` with resource `key.Public.ID()` (empty on failure) and details `url + " allow_private=" + strconv.FormatBool(s.Cfg.BackupAllowPrivateRecovery)`; on error `backupFail`; else 200 `{"paired": true, "recovery_key_id": id}`.
- `backupPinKey`: decode `{public_key string, threshold, total_shares int}`; `s.PinKey`; audit `backup.key_pinned`; 200 `{"recovery_key_id": id, "threshold": k, "total_shares": n}`.
- `backupUnpair`: `s.Unpair()`; audit `backup.unpaired` with details `"url and sealed token rows removed; key pin kept"`; 200 `{"unpaired": true, "note": "Rows removed. The credential is dead only when the KyRecovery admin revokes it."}`.
- `backupSchedule`: decode `{interval_sec int64}`; `got, err := s.SetSchedule(sec)`; audit `backup.schedule` with details `strconv.FormatInt(int64(got/time.Second), 10)`; 200 `{"interval_sec": got/time.Second}`.
- `backupRun` (route stays `POST /api/v1/backup/deposit`): `ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 16*time.Minute)`; `res, err := s.Run(ctx)`; `action, outcome, details := recoveryclient.Outcome(res, err)` (action is the library's `admin.backup_run`); `b, _ := json.Marshal(details)`; audit with resource `res.Manifest.CapsuleID` and `Details: string(b)` written directly, not through `AuditSafe`, because every value in the map is already bounded by the library and truncating the JSON would corrupt it; on `err != nil && !errors.Is(err, recoveryclient.ErrReceiptUnrecorded)` → `backupFail`; else 200 JSON `res`.
- `backupExport`: `raw, m, err := s.Export()`; on error audit `backup.export_failed` and `backupFail`; audit `backup.exported` and if that write fails → 503 `audit_failed` with no body bytes; else set `Content-Type: application/octet-stream`, `Content-Disposition: attachment; filename="KyDNS.<capsule-id>.kycap"`, `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, write.
- `backupDrill`: `s.Drill(r.Context())`; audit `backup.drill`; 200 JSON.

In `api.go`: change field to `backup *backup.Service`, `WithBackupService(s *backup.Service)`, and routes:

```go
	mux.HandleFunc("POST /api/v1/backup/drill", auth(a.backupDrill))
	mux.HandleFunc("GET /api/v1/backup/export-capsule", auth(a.backupExport))
	mux.HandleFunc("POST /api/v1/backup/pair-remote", auth(a.backupPair))
	mux.HandleFunc("POST /api/v1/backup/pin-key", auth(a.backupPinKey))
	mux.HandleFunc("DELETE /api/v1/backup/pairing", auth(a.backupUnpair))
	mux.HandleFunc("PUT /api/v1/backup/schedule", auth(a.backupSchedule))
	mux.HandleFunc("POST /api/v1/backup/deposit", auth(a.backupRun))
	mux.HandleFunc("GET /api/v1/backup/status", auth(a.backupStatus))
```

- [ ] **Step 4: Rewire serve.go and replace the loop**

At `serve.go:303`:

```go
	backupSvc, err := backup.New(cfg, st, web.Version)
	if err != nil {
		return err
	}
	if cfg.BackupAllowPrivateRecovery {
		logger.Warn("KYDNS_BACKUP_ALLOW_PRIVATE_RECOVERY is set: private and CGNAT KyRecovery addresses admitted; HTTPS still required")
	}
```

Replace the `if cfg.BackupDepositInterval > 0 { go depositLoop(...) }` with an unconditional `go backupLoop(ctx, backupSvc, logger)` and replace `depositLoop` with:

```go
// backupLoop polls the schedule every minute so an admin's change needs no restart. The
// next run counts from the last attempt, successful or not, so a dead destination is
// retried once per interval. An upload already started outlives SIGTERM.
func backupLoop(ctx context.Context, svc *backup.Service, logger *slog.Logger) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		st, err := svc.Status()
		if err != nil {
			logger.Error("backup schedule unreadable", "error", recoveryclient.AuditSafe(err.Error()))
			continue
		}
		if st.NextRun == nil || time.Now().Before(*st.NextRun) {
			continue
		}
		upload, cancel := context.WithTimeout(context.WithoutCancel(ctx), 16*time.Minute)
		res, err := svc.Run(upload)
		cancel()
		if errors.Is(err, recoveryclient.ErrNotPaired) || errors.Is(err, recoveryclient.ErrNoDestination) {
			continue
		}
		action, outcome, details := recoveryclient.Outcome(res, err)
		b, _ := json.Marshal(details)
		_ = svc.Store.RecordAudit(store.AuditEvent{Actor: "scheduler", Action: action, Resource: res.Manifest.CapsuleID, Details: string(b), Outcome: outcome})
		if err != nil {
			logger.Error("scheduled backup failed", "error", recoveryclient.AuditSafe(err.Error()))
		}
	}
}
```

`serve.go` gains imports `encoding/json` and `github.com/Busness-app/ky-primitives/recoveryclient`. Pass `backupSvc` to `web.Options.Backup` as before; Task 8 changes that field's type.

- [ ] **Step 5: Run the tests**

Run: `go test -race ./internal/adminapi ./internal/app`
Expected: PASS once Task 8's web changes compile; if `internal/web` blocks the build, do Task 8 Step 3 first, then return here.

- [ ] **Step 6: Commit**

```bash
git add internal/adminapi internal/app
git commit -m "feat(api): backup pin-key, unpair, schedule and unified run on recoveryclient

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 8: Settings screen, CLI, and the decrypt guard

**Files:**
- Rewrite: `internal/web/backup.go`
- Modify: `internal/web/middleware.go:69-70` (`Backup *backup.Service`), `internal/web/pages.go:62-65` (routes), `internal/web/settings.go:106-112` (status into template data), `internal/web/templates/settings.html:259-291` (the backup block)
- Modify: `internal/web/static/app.css` (only if a `.facts` grid class is needed; prefer existing `.card`, `.actions`, `.stack`, `.muted`, `table.grid`)
- Create: `internal/web/backup_test.go`
- Modify: `cmd/kydns/main.go:93-131` (restore via the library), `internal/cli/cli.go:134-176` (add `backup-pin-key`, `backup-unpair`, `backup-schedule`; keep `backup-drill`, `export-capsule`, `deposit`)
- Create: `internal/backup/nodecrypt_test.go`

**Interfaces:**
- Consumes: `backup.Service`, `backup.Status` from Task 6.
- Produces web routes: existing `GET /settings/backup/export`, `POST /settings/backup/{pair,deposit,drill}`; new `POST /settings/backup/pin-key`, `POST /settings/backup/unpair`, `POST /settings/backup/schedule`. All POSTs behind `requireCSRF`.

- [ ] **Step 1: Write the failing web tests**

`internal/web/backup_test.go`, using `loggedIn(t, tweak)` and `postForm` from the existing tests. The `tweak` sets `o.Backup` to a `backup.Service` over the test store with a temp `DataDir`:

```go
func TestBackupSectionWarnsWithoutKeyAndDestination(t *testing.T) {
	h, _, c, _ := loggedInWithBackup(t, "")
	body := get(t, h, "/settings", c)
	for _, want := range []string{"No recovery key", "Nowhere to put a capsule", "Pin the suite key by hand"} {
		if !strings.Contains(body, want) {
			t.Errorf("settings page lacks %q", want)
		}
	}
}

func TestBackupPinKeyThenRunWritesLocalCopy(t *testing.T) {
	dir := t.TempDir()
	h, srv, c, csrf := loggedInWithBackup(t, dir)
	rr := postForm(t, h, "/settings/backup/pin-key", url.Values{"public_key": {freshPublicKeyB64(t)}, "threshold": {"2"}, "total_shares": {"3"}, "csrf_token": {csrf}}, c)
	if rr.Code != 303 {
		t.Fatalf("pin-key = %d %s", rr.Code, rr.Body)
	}
	rr = postForm(t, h, "/settings/backup/deposit", url.Values{"csrf_token": {csrf}}, c)
	if rr.Code != 303 {
		t.Fatalf("run = %d %s", rr.Code, rr.Body)
	}
	copies, _ := recoveryclient.ListLocalCopies(dir, backup.ServiceName)
	if len(copies) != 1 {
		t.Fatalf("copies = %d", len(copies))
	}
	body := get(t, h, "/settings", c)
	if !strings.Contains(body, copies[0].Name) || !strings.Contains(body, "Schedule") {
		t.Fatal("settings page does not show the local copy and schedule card")
	}
	_ = srv
}

func TestBackupPostsNeedCSRF(t *testing.T) {
	h, _, c, _ := loggedInWithBackup(t, "")
	for _, p := range []string{"/settings/backup/pin-key", "/settings/backup/unpair", "/settings/backup/schedule", "/settings/backup/deposit", "/settings/backup/drill", "/settings/backup/pair"} {
		if rr := postForm(t, h, p, url.Values{}, c); rr.Code != 403 {
			t.Errorf("%s without csrf = %d", p, rr.Code)
		}
	}
}

func TestBackupPageNeverShowsTheToken(t *testing.T) {
	h, srv, c, _ := loggedInWithBackup(t, "")
	pinViaService(t, srv)
	if err := recoveryclient.StorePairing(srv.o.Backup.Settings(), srv.o.Backup.Sealer(), "https://recovery.example", "plain-secret-token"); err != nil {
		t.Fatal(err)
	}
	body := get(t, h, "/settings", c)
	if strings.Contains(body, "plain-secret-token") {
		t.Fatal("token rendered")
	}
	if !strings.Contains(body, "recovery.example") || !strings.Contains(body, "Unpair") {
		t.Fatal("pairing panel missing")
	}
}

func TestBackupScheduleFormRejectsBelowFloor(t *testing.T) {
	h, _, c, csrf := loggedInWithBackup(t, "")
	rr := postForm(t, h, "/settings/backup/schedule", url.Values{"interval_minutes": {"5"}, "csrf_token": {csrf}}, c)
	if rr.Code != 400 || !strings.Contains(rr.Body.String(), "15") {
		t.Fatalf("schedule 5m = %d %s", rr.Code, rr.Body)
	}
}

func TestBackupTemplateHasNoInlineHandlers(t *testing.T) {
	b, _ := os.ReadFile("templates/settings.html")
	if regexp.MustCompile(`\son[a-z]+=`).Match(b) {
		t.Fatal("inline event handler in settings.html")
	}
}
```

Write `loggedInWithBackup(t, dir)` to call `loggedIn` with a tweak that builds `backup.New(&config.Config{DataDir: t.TempDir(), BackupDir: dir, BackupKeep: 7, ...}, o.Store, "test")`; look at how `loggedIn` exposes the store in `services_test.go:15`.

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/web -run TestBackup 2>&1 | head`
Expected: compile failure.

- [ ] **Step 3: Rewrite web/backup.go**

Handlers mirror the API ones in Task 7 but read form values and redirect to `/settings` (303) on success or render `settings.html` with the error (400, via the existing `backupError`). Actor `admin`, IP `r.RemoteAddr`, every outcome audited through `recoveryclient.Outcome` for runs. New handlers:

```go
func (s *Server) postBackupPinKey(w http.ResponseWriter, r *http.Request) {
	b := s.o.Backup
	if b == nil {
		s.backupError(w, r, errors.New("backup service is unavailable"))
		return
	}
	k, _ := strconv.Atoi(r.PostFormValue("threshold"))
	n, _ := strconv.Atoi(r.PostFormValue("total_shares"))
	key, err := b.PinKey(r.PostFormValue("public_key"), k, n)
	s.auditBackup(b, r, "backup.key_pinned", key.Public.ID(), fmt.Sprintf("%d-of-%d %v", k, n, err), err)
	if err != nil {
		s.backupError(w, r, err)
		return
	}
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

func (s *Server) postBackupUnpair(w http.ResponseWriter, r *http.Request) {
	b := s.o.Backup
	if b == nil {
		s.backupError(w, r, errors.New("backup service is unavailable"))
		return
	}
	err := b.Unpair()
	s.auditBackup(b, r, "backup.unpaired", "", "url and sealed token rows removed; key pin kept", err)
	if err != nil {
		s.backupError(w, r, err)
		return
	}
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

func (s *Server) postBackupSchedule(w http.ResponseWriter, r *http.Request) {
	b := s.o.Backup
	if b == nil {
		s.backupError(w, r, errors.New("backup service is unavailable"))
		return
	}
	minutes, err := strconv.ParseInt(r.PostFormValue("interval_minutes"), 10, 64)
	if err != nil || minutes < 0 || minutes > int64(recoveryclient.MaxInterval/time.Minute) {
		s.backupError(w, r, recoveryclient.ErrBadInterval)
		return
	}
	got, err := b.SetSchedule(minutes * 60)
	s.auditBackup(b, r, "backup.schedule", "", strconv.FormatInt(int64(got/time.Second), 10), err)
	if err != nil {
		s.backupError(w, r, err)
		return
	}
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}
```

`auditBackup` is a small helper writing `store.AuditEvent{Actor: "admin", Action: action, Resource: recoveryclient.AuditSafe(resource), Details: recoveryclient.AuditSafe(details), IP: recoveryclient.AuditSafe(r.RemoteAddr), Outcome: "success"|"failure"}`. Register in `pages.go`:

```go
	mux.HandleFunc("POST /settings/backup/pin-key", s.requireCSRF(s.postBackupPinKey))
	mux.HandleFunc("POST /settings/backup/unpair", s.requireCSRF(s.postBackupUnpair))
	mux.HandleFunc("POST /settings/backup/schedule", s.requireCSRF(s.postBackupSchedule))
```

In `settings.go:106-112` call `s.o.Backup.Status()` and put the whole `backup.Status` under `data["Backup"]`.

- [ ] **Step 4: Rewrite the template block**

Replace `settings.html:270-290` (`{{with .Backup}} ... {{end}}`) with a "Disaster recovery" card containing, in order:

1. **Warnings** (each a `<p class="muted">`, shown by condition): `{{if not .KeyPinned}}No recovery key. Pair with KyRecovery or pin the suite key by hand below.{{end}}`, `{{if .KeyPinMissing}}Paired, but recovery.pub is missing or does not match the pin. Restore the file or re-pair; a different key is refused.{{end}}`, `{{if and .KeyPinned (not .HasDestination)}}Nowhere to put a capsule. Pair with KyRecovery or set KYDNS_BACKUP_DIR.{{end}}`, `{{if eq .IntervalSec 0}}Schedule is off. Backups run only when you click.{{end}}`.
2. **Four fact cards** as a `<table class="grid">` with four rows (KyDNS's UI has no card grid; a table is the existing pattern): Recovery key (`{{.RecoveryKeyID}}`, `{{.Threshold}}-of-{{.TotalShares}}`, or "not pinned"); KyRecovery (`{{.RecoveryURL}}` and last verified deposit `{{.LastDeposit.CapsuleID}}` at `{{.LastDeposit.DepositedAt}}`, or "not paired"; "private addresses admitted" when `.AllowPrivate`); Local copies (`{{.LocalDir}}`, keep `{{.LocalKeep}}`, newest `{{(index .LocalCopies 0).Name}}` guarded by `{{if .LocalCopies}}`, or "KYDNS_BACKUP_DIR not set"); Schedule (every N minutes, next run `{{.NextRun}}`, or "off").
3. **Action row** `<div class="actions">`: forms for `/settings/backup/deposit` ("Back up now"), `/settings/backup/drill` ("Run drill"), and the link `/settings/backup/export` ("Download capsule"), each with the CSRF hidden input and `{{template "ro" $}}`.
4. **What a capsule carries**: one `<p class="muted">`: database, backup_key, node_key when replicated, config manifest; sealed to the suite key; this server cannot open it.
5. **Schedule form**: `<form method="post" action="/settings/backup/schedule">` with `<label for="interval_minutes">Back up every (minutes; 0 turns it off; at least 15)</label><input id="interval_minutes" name="interval_minutes" type="number" min="0" step="1" value="{{div .IntervalSec 60}}">` (add a `div` func to the template funcmap if there is none; otherwise precompute `IntervalMinutes` in `settings.go`).
6. **Pairing panel**: when paired, URL plus an Unpair form with the sentence "Removes the URL and sealed token rows. The key pin, receipts and local copies stay. The credential is dead only when the KyRecovery admin revokes it." When not paired, the existing URL + six-digit code form.
7. **Key-by-hand panel**: `<form method="post" action="/settings/backup/pin-key">` with `public_key` (textarea, base64 from the ceremony page), `threshold`, `total_shares`; hidden when `.KeyPinned`.

No inline handlers. Keep every label visible; keyboard order follows document order.

- [ ] **Step 5: CLI**

`cmd/kydns/main.go` restore case becomes:

```go
	case "restore":
		fs := flag.NewFlagSet("restore", flag.ContinueOnError)
		fs.SetOutput(stdout)
		capsulePath := fs.String("capsule", "", "sealed capsule path")
		out := fs.String("out", "", "empty restore directory")
		if err := fs.Parse(args[1:]); err != nil || *capsulePath == "" || *out == "" || fs.NArg() > 0 {
			fmt.Fprintln(stdout, "usage: kydns restore --capsule path --out directory   (shares on stdin, one per line)")
			return 2
		}
		shares, err := recoveryclient.ReadShares(os.Stdin)
		if err == nil {
			err = recoveryclient.Restore(*capsulePath, *out, backup.ServiceName, shares, stdout)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "kydns:", err)
			return 1
		}
		return 0
```

`fs.NArg() > 0` makes a share on argv a usage error, which `scripts/restore-drill.sh` already checks. In `internal/cli/cli.go` add three API-backed commands beside `deposit`: `backup-pin-key --public-key-file PATH --threshold K --total-shares N` (reads the base64 from a file, never argv, and POSTs `pin-key`), `backup-unpair` (DELETE `pairing`), `backup-schedule --minutes N` (PUT `schedule`). Follow the shape of `backupDrillCmd` at `cli.go:138`. Update the `usage` constant in `main.go`.

- [ ] **Step 6: Decrypt guard**

`internal/backup/nodecrypt_test.go`:

```go
package backup_test

import (
	"path/filepath"
	"testing"

	"github.com/Busness-app/ky-primitives/recoveryclient/guardtest"
)

// Only the restore command may combine shares or open a suite-sealed capsule. The drill
// opens a capsule sealed to a throwaway key inside the library, not here.
func TestNothingInTheServerDecrypts(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	guardtest.NoDecryptOutside(t, root, map[string][]string{
		filepath.Join("cmd", "kydns", "main.go"): {"run"},
	})
}
```

Prove it is not vacuous once: add `capsule.Open(nil, recoverykey.PrivateKey{}, "")` inside `internal/web/backup.go` temporarily, run `go test ./internal/backup -run TestNothingInTheServerDecrypts`, see it FAIL naming the file, then remove the line. Record the failing output in the commit body.

- [ ] **Step 7: Run everything**

Run: `gofmt -l . ; go vet ./... ; go test -race ./... ; git diff --check`
Expected: no gofmt output, vet clean, all `ok`, no whitespace errors.

- [ ] **Step 8: Run the restore drill against the new implementation**

Run: `scripts/restore-drill.sh`
Expected: `restore drill: all checks passed`. If the library's `Restore` prints the manifest, update `docs/RESTORE.md` Step 2 to say what to compare.

- [ ] **Step 9: Commit**

```bash
git add internal/web internal/backup/nodecrypt_test.go cmd/kydns internal/cli
git commit -m "feat(web,cli): disaster recovery screen, pin-key, unpair, schedule, decrypt guard

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 9: Docs sweep, live proof, PR

**Files:**
- Modify: `README.md` (remove the `(Phase B)` marker; name the screen; list `backup-pin-key`, `backup-unpair`, `backup-schedule`), `AGENTS.md:77` (`internal/backup` line now says "adapter over ky-primitives/recoveryclient"), `DESGINE.md:294-296`, `LOGGING.md:49` (add actions `backup.key_pinned`, `backup.unpaired`, `backup.schedule`, and the library-fixed `admin.backup_run` whose details column is a JSON object), `SECURITY.md` (unpair semantics, pin-by-hand), `docs/RESTORE.md` (Step 4 mentions the Disaster recovery card by its heading), `CONTRIBUTING.md:42` (add `scripts/restore-drill.sh` to the backup gate)

- [ ] **Step 1: Docs**

Make each edit above. Then check that every route and command named in docs exists:

```bash
grep -oh '/api/v1/backup/[a-z-]*' README.md SECURITY.md AGENTS.md DESGINE.md | sort -u > /tmp/doc-routes
grep -oh '/api/v1/backup/[a-z-]*' internal/adminapi/api.go | sort -u > /tmp/code-routes
diff /tmp/doc-routes /tmp/code-routes
```

Expected: no diff, or only routes the code has that docs do not mention.

- [ ] **Step 2: Live proof on a throwaway data dir**

```bash
go build -o /tmp/kydns ./cmd/kydns
mkdir -p /tmp/kydns-live/data /tmp/kydns-live/backups
printf 'data_dir: /tmp/kydns-live/data\ndns:\n  listen: "127.0.0.1:5353"\nadmin:\n  listen: "127.0.0.1:8053"\n' > /tmp/kydns-live/kydns.yaml
KYDNS_BACKUP_DIR=/tmp/kydns-live/backups /tmp/kydns serve --config /tmp/kydns-live/kydns.yaml
```

In a browser: complete setup with the logged setup token, open Settings, confirm the three warnings, pin a fresh key (generate one with the throwaway program from `scripts/restore-drill.sh`, base64 of the public bytes), click Back up now, then:

```bash
ls -la /tmp/kydns-live/backups          # one KyDNS.*.kycap at -rw-------
sqlite3 /tmp/kydns-live/data/kydns.db "SELECT action, outcome FROM audit_events ORDER BY id"   # backup.key_pinned success, admin.backup_run success
```

Set the schedule to 15 minutes and confirm the card shows the next run; set it to 0 and confirm the "Schedule is off" warning. Stop the server; `rm -rf /tmp/kydns-live`.

- [ ] **Step 3: Live pairing in the homelab (Yoshi's environment only)**

Follow the spec's proving section: `KYDNS_BACKUP_ALLOW_PRIVATE_RECOVERY=true` in `.env`, then `KYDNS_DNS=192.168.1.1 docker compose -f docker-compose.yml -f docker-compose.lan-dns.yml up -d --force-recreate`, `docker inspect kydns --format '{{.HostConfig.Dns}}'` shows `[192.168.1.1]`, pair with a code from the KyRecovery dashboard, Back up now, confirm the capsule in the KyRecovery dashboard with matching digest. If the environment is not available in the session, say so in the PR and the board post; do not claim it.

- [ ] **Step 4: Full gate and PR**

```bash
gofmt -l . ; go vet ./... ; go test -race ./... ; scripts/restore-drill.sh ; git diff --check
```

Use the `pull-request` skill. Title: `feat(backup): bring KyRecovery integration to the suite spec on ky-primitives/recoveryclient`. Body lists the 14 spec rows with a check or the reason it is not applicable, the decrypt-guard proof output, and what was proven live versus in unit tests only. Expect two to three reviewer rounds; the hazards list in the spec is what the reviewer looks for.

- [ ] **Step 5: Hand-off**

Post to MySlop folder `kydns-kyrecovery-deposit` with the header (Repo, PR URL, worktree), what landed, what is still unproven (live pairing if it did not happen), and set `status=done` once merged.

---

## Self-review against the spec (rows from post 192)

| Row | Requirement | Task |
|---|---|---|
| 1 | Pair: service_name, write-once pin, sealed token with label | 6 (`Pair`, `NewAESGCMSealer(key, "KyDNS:kyrecovery_token")`) |
| 2 | Pin by hand, write-once, 409 | 6 (`PinKey`), 7 (route), 8 (form) |
| 3 | One run, every destination, 412 with no destination | 6 (`Run`), 7 (`backupRun`), 8 (Back up now) |
| 4 | Local dir + keep, own prefix only, local failure never cancels | 2 (config), 6 (via library), test `TestRunWritesALocalCopyOnlyKeyOpens` |
| 5 | Schedule is an admin setting, polled each minute, counts from last attempt, reads back | 6 (`SetSchedule`), 7 (`backupLoop`, route), 8 (form) |
| 6 | Unpair rows only, honest text | 6 (`Unpair`), 7, 8 |
| 7 | `KYDNS_BACKUP_ALLOW_PRIVATE_RECOVERY` | 2 (config), 6 (`NewClient(Options)`), 7 (startup log, pairing audit details) |
| 8 | Compose override file, env pass-through | 3 |
| 9 | Screen: facts, action row, capsule contents, schedule form, pairing with Unpair, key by hand, warnings | 8 |
| 10 | Destructive routes behind the product gate and in the hardening test | 7 (write-gate table), 8 (`TestBackupPostsNeedCSRF`) |
| 11 | Decrypt guard via `guardtest` | 8 |
| 12 | `docs/RESTORE.md` proven in a scratch run | 4, re-proven in 8 Step 8 |
| 13 | README TLS/fingerprint/env vars; package AGENTS.md | 5, 6 Step 6, 9 |
| 14 | Stale spec deleted | already absent; verified by `git ls-files` |

Hazards from the reviewer list, where the plan pins each: own-prefix prune (Task 6 test), local failure carried not fatal (library; `Outcome` in Task 7), seconds bound before Duration math (Task 6 `TestScheduleIsBoundedInSeconds` includes 2^55), read-back for audit (Task 6 `SetSchedule`), no `dns:` in the base compose (Task 3), CGNAT by name (library), honest unpair text (Tasks 7, 8), no inline handlers (Task 8 test), runbook empty-volume gate and old-volume copy (Task 4), guard non-vacuous (Task 8 Step 6).

## Hard stops

- A later ky-primitives tag changes `Run`, `Outcome` or `Drill`: stay on v0.5.0 for this PR and post the delta to `ky-primitives-kyrecovery-package`; do not re-implement the difference in KyDNS.
- A live-paired KyDNS instance exists before Phase B lands: the sealed-token format change in Task 6 breaks it; add an explicit "re-pair required" note to the PR and the screen, still no fallback decoder.
