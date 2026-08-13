# Linked-Server Replication: Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A KyDNS replica pulls its configuration from a linked primary over an authenticated TLS link and serves DNS from it, with no operator surface yet.

**Architecture:** The primary keeps a `config_version` bumped by SQL triggers on replicated tables only. A replica polls that version, and on a change pulls the whole configuration document and applies it in one transaction. Peers are enrolled once by a single-use pairing code exchanged as a PAKE secret, then authenticate on pinned Ed25519 key fingerprints forever after.

**Tech Stack:** Go 1.26.5, `modernc.org/sqlite`, `crypto/tls`, `crypto/ed25519`, one new PAKE dependency selected in Task 6.

**Spec:** `docs/superpowers/specs/2026-08-13-kydns-linked-server-replication-design.md`

**Scope:** This plan is part 1 of 2. It delivers replication driven by the config file and the package API. Part 2 delivers the operator surface: the read-only write gate, health-status replication, CLI verbs, web UI, and promotion/demotion.

## Global Constraints

- Module path is `github.com/yoshiofthewire/kydns-server`. All internal imports use it.
- Tests run with `CGO_ENABLED=0 go test ./...` (`make test`). Build with `make build`.
- Every security property is tested, never asserted in a comment. Each security test must be run and seen to FAIL before its implementation exists. A test that has never failed is not evidence.
- The store is the only place that holds SQL. No SQL outside `internal/store`.
- Replicated settings: `private_domain`, `reverse_zones`, `upstreams`, `allow_query`, `allow_tailscale`, `ttl`, `cache_min_ttl`, `cache_max_ttl`, `negative_max_ttl`, `cache_entries`, `health_interval`, `health_timeout`, `health_workers`.
- Node-local settings, never overwritten by a snapshot: `dhcp_lease_file`, `discovery_interval`, `log_queries`, `log_client_ip`.
- Never replicated: API tokens, the admin account, blacklist list bodies (`snapshot`, `etag`, `last_modified`, `last_attempt_at`, `last_ok_at`, `last_error`, `entry_count`, `skipped_count`), DNS query history.
- Poll interval 5s. Backoff ceiling and staleness threshold both 60s.
- `SchemaVersion` for the replication wire format starts at 1. A mismatch is refused, never coerced.

## Deviations from the spec, decided here

1. **`config_version` is maintained by SQL triggers, not by Go code at each write site.** The spec says "incremented in the same transaction as any write to replicated state." Triggers give exactly that, and a write path added later cannot forget to bump. It also pushes the replicated / node-local settings split into SQL, where it is enforced rather than remembered.
2. **Snapshot apply needs a new transactional store method.** The spec assumes the existing import-replace path is one transaction. It is not — `internal/adminapi/api.go:608-630` calls `reg.ReplaceAll`, then `applyBlacklistDoc`, then `applySettingsDoc` in sequence, so a failure partway leaves a half-applied configuration. The spec's promise that a bad snapshot leaves the previous configuration intact requires a real transaction, added in Task 5.

---

### Task 1: `config_version` and its triggers

**Files:**
- Modify: `internal/store/store.go` (append to `schema`, append to `migrations`)
- Create: `internal/store/version.go`
- Test: `internal/store/version_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `func (s *Store) ConfigVersion() (int64, error)`.

- [ ] **Step 1: Write the failing tests**

Create `internal/store/version_test.go`:

```go
package store

import "testing"

func TestConfigVersionStartsAtZero(t *testing.T) {
	s := open(t)
	v, err := s.ConfigVersion()
	if err != nil {
		t.Fatal(err)
	}
	if v != 0 {
		t.Fatalf("ConfigVersion() = %d, want 0", v)
	}
}

func TestServiceWriteBumpsConfigVersion(t *testing.T) {
	s := open(t)
	before, err := s.ConfigVersion()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.PutService(Service{Name: "kypost"}); err != nil {
		t.Fatal(err)
	}
	after, err := s.ConfigVersion()
	if err != nil {
		t.Fatal(err)
	}
	if after <= before {
		t.Fatalf("ConfigVersion() = %d after a service write, want > %d", after, before)
	}
}

// A token is node-local. Replicating on a token write would wake every replica
// for a change none of them will ever receive.
func TestTokenWriteDoesNotBumpConfigVersion(t *testing.T) {
	s := open(t)
	before, err := s.ConfigVersion()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.PutToken(Token{Label: "cli", Hash: "abc"}); err != nil {
		t.Fatal(err)
	}
	after, err := s.ConfigVersion()
	if err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("ConfigVersion() = %d after a token write, want %d", after, before)
	}
}

func TestRecordDeleteBumpsConfigVersion(t *testing.T) {
	s := open(t)
	r, err := s.PutRecord(Record{Name: "nas.home.arpa.", Type: "A", Value: "192.168.1.5"})
	if err != nil {
		t.Fatal(err)
	}
	before, err := s.ConfigVersion()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteRecord(r.ID); err != nil {
		t.Fatal(err)
	}
	after, err := s.ConfigVersion()
	if err != nil {
		t.Fatal(err)
	}
	if after <= before {
		t.Fatalf("ConfigVersion() = %d after a delete, want > %d", after, before)
	}
}

// A blacklist refresh writes the downloaded body and its cache validators on
// every poll. Those are node-local, so they must not look like a config change.
func TestBlacklistBodyWriteDoesNotBumpConfigVersion(t *testing.T) {
	s := open(t)
	l, err := s.PutBlacklistList(BlacklistList{Name: "steven", URL: "https://example.test/hosts", Format: "hosts"})
	if err != nil {
		t.Fatal(err)
	}
	before, err := s.ConfigVersion()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SaveBlacklistSnapshot(l.ID, []string{"ads.example"}, "etag-1", "Mon, 01 Jan 2029 00:00:00 GMT"); err != nil {
		t.Fatal(err)
	}
	after, err := s.ConfigVersion()
	if err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("ConfigVersion() = %d after a snapshot write, want %d", after, before)
	}
}

// The node-local settings keys must not wake replicas either.
func TestSettingsSplitBumpsOnlyForReplicatedKeys(t *testing.T) {
	s := open(t)
	base := Settings{PrivateDomain: "home.arpa", TTL: 60, CacheMinTTL: 5,
		CacheMaxTTL: 3600, NegativeMaxTTL: 300, CacheEntries: 10000,
		DiscoveryInterval: 30, HealthInterval: 30, HealthTimeout: 5, HealthWorkers: 8}
	if err := s.PutSettings(base); err != nil {
		t.Fatal(err)
	}

	before, err := s.ConfigVersion()
	if err != nil {
		t.Fatal(err)
	}
	local := base
	local.LogQueries = true
	if err := s.PutSettings(local); err != nil {
		t.Fatal(err)
	}
	mid, err := s.ConfigVersion()
	if err != nil {
		t.Fatal(err)
	}
	if mid != before {
		t.Fatalf("ConfigVersion() = %d after a log_queries write, want %d", mid, before)
	}

	shared := local
	shared.TTL = 120
	if err := s.PutSettings(shared); err != nil {
		t.Fatal(err)
	}
	after, err := s.ConfigVersion()
	if err != nil {
		t.Fatal(err)
	}
	if after <= mid {
		t.Fatalf("ConfigVersion() = %d after a ttl write, want > %d", after, mid)
	}
}
```

Note: if `PutToken`, `DeleteRecord`, `PutBlacklistList`, or `SaveBlacklistSnapshot` have different names or signatures in the store, use the real ones — do not add wrappers to satisfy this test. Run `grep -n "func (s \*Store)" internal/store/*.go` to get the exact list first.

- [ ] **Step 2: Run the tests to verify they fail**

```bash
CGO_ENABLED=0 go test ./internal/store/ -run ConfigVersion -v
```

Expected: FAIL — `s.ConfigVersion undefined`.

- [ ] **Step 3: Add the table and triggers to the schema**

Append to the `schema` constant in `internal/store/store.go`, before the closing backtick:

```sql
CREATE TABLE IF NOT EXISTS config_version (
  id      INTEGER PRIMARY KEY CHECK (id = 1),
  version INTEGER NOT NULL DEFAULT 0
);
INSERT OR IGNORE INTO config_version(id, version) VALUES(1, 0);
```

Then add the trigger set. Put it in one place so the replicated surface is
readable as a list. Append to `schema` as well:

```sql
-- config_version is bumped by triggers rather than by Go, so a write path
-- added later cannot forget to bump it. The columns named in the UPDATE OF
-- clauses ARE the replicated settings split: anything absent is node-local
-- and deliberately invisible to replicas.
CREATE TRIGGER IF NOT EXISTS cv_views_i AFTER INSERT ON views BEGIN
  UPDATE config_version SET version = version + 1 WHERE id = 1; END;
CREATE TRIGGER IF NOT EXISTS cv_views_d AFTER DELETE ON views BEGIN
  UPDATE config_version SET version = version + 1 WHERE id = 1; END;
CREATE TRIGGER IF NOT EXISTS cv_view_subnets_i AFTER INSERT ON view_subnets BEGIN
  UPDATE config_version SET version = version + 1 WHERE id = 1; END;
CREATE TRIGGER IF NOT EXISTS cv_view_subnets_d AFTER DELETE ON view_subnets BEGIN
  UPDATE config_version SET version = version + 1 WHERE id = 1; END;
CREATE TRIGGER IF NOT EXISTS cv_services_i AFTER INSERT ON services BEGIN
  UPDATE config_version SET version = version + 1 WHERE id = 1; END;
CREATE TRIGGER IF NOT EXISTS cv_services_u AFTER UPDATE ON services BEGIN
  UPDATE config_version SET version = version + 1 WHERE id = 1; END;
CREATE TRIGGER IF NOT EXISTS cv_services_d AFTER DELETE ON services BEGIN
  UPDATE config_version SET version = version + 1 WHERE id = 1; END;
CREATE TRIGGER IF NOT EXISTS cv_service_addresses_i AFTER INSERT ON service_addresses BEGIN
  UPDATE config_version SET version = version + 1 WHERE id = 1; END;
CREATE TRIGGER IF NOT EXISTS cv_service_addresses_u AFTER UPDATE ON service_addresses BEGIN
  UPDATE config_version SET version = version + 1 WHERE id = 1; END;
CREATE TRIGGER IF NOT EXISTS cv_service_addresses_d AFTER DELETE ON service_addresses BEGIN
  UPDATE config_version SET version = version + 1 WHERE id = 1; END;
CREATE TRIGGER IF NOT EXISTS cv_aliases_i AFTER INSERT ON aliases BEGIN
  UPDATE config_version SET version = version + 1 WHERE id = 1; END;
CREATE TRIGGER IF NOT EXISTS cv_aliases_d AFTER DELETE ON aliases BEGIN
  UPDATE config_version SET version = version + 1 WHERE id = 1; END;
CREATE TRIGGER IF NOT EXISTS cv_records_i AFTER INSERT ON records BEGIN
  UPDATE config_version SET version = version + 1 WHERE id = 1; END;
CREATE TRIGGER IF NOT EXISTS cv_records_u AFTER UPDATE ON records BEGIN
  UPDATE config_version SET version = version + 1 WHERE id = 1; END;
CREATE TRIGGER IF NOT EXISTS cv_records_d AFTER DELETE ON records BEGIN
  UPDATE config_version SET version = version + 1 WHERE id = 1; END;
CREATE TRIGGER IF NOT EXISTS cv_blacklist_settings_u AFTER UPDATE ON blacklist_settings BEGIN
  UPDATE config_version SET version = version + 1 WHERE id = 1; END;
CREATE TRIGGER IF NOT EXISTS cv_blacklist_rules_i AFTER INSERT ON blacklist_rules BEGIN
  UPDATE config_version SET version = version + 1 WHERE id = 1; END;
CREATE TRIGGER IF NOT EXISTS cv_blacklist_rules_u AFTER UPDATE ON blacklist_rules BEGIN
  UPDATE config_version SET version = version + 1 WHERE id = 1; END;
CREATE TRIGGER IF NOT EXISTS cv_blacklist_rules_d AFTER DELETE ON blacklist_rules BEGIN
  UPDATE config_version SET version = version + 1 WHERE id = 1; END;
-- Definition columns only. A refresh writes snapshot, etag, last_modified and
-- the counters on every poll; those are node-local and must not look like a
-- configuration change.
CREATE TRIGGER IF NOT EXISTS cv_blacklist_lists_i AFTER INSERT ON blacklist_lists BEGIN
  UPDATE config_version SET version = version + 1 WHERE id = 1; END;
CREATE TRIGGER IF NOT EXISTS cv_blacklist_lists_d AFTER DELETE ON blacklist_lists BEGIN
  UPDATE config_version SET version = version + 1 WHERE id = 1; END;
CREATE TRIGGER IF NOT EXISTS cv_blacklist_lists_u AFTER UPDATE OF
  name, url, format, description, enabled, builtin, interval_seconds
  ON blacklist_lists BEGIN
  UPDATE config_version SET version = version + 1 WHERE id = 1; END;
-- Replicated settings columns only. dhcp_lease_file, discovery_interval,
-- log_queries and log_client_ip are absent on purpose: they are node-local.
CREATE TRIGGER IF NOT EXISTS cv_settings_i AFTER INSERT ON settings BEGIN
  UPDATE config_version SET version = version + 1 WHERE id = 1; END;
CREATE TRIGGER IF NOT EXISTS cv_settings_u AFTER UPDATE OF
  private_domain, reverse_zones, upstreams, allow_query, allow_tailscale,
  ttl, cache_min_ttl, cache_max_ttl, negative_max_ttl, cache_entries,
  health_interval, health_timeout, health_workers
  ON settings BEGIN
  UPDATE config_version SET version = version + 1 WHERE id = 1; END;
```

- [ ] **Step 4: Add the same statements as a migration**

An existing database has none of this. Append one new entry to the
`migrations` slice in `internal/store/store.go` containing the **exact same
SQL** as Step 3 (the table, the `INSERT OR IGNORE`, and every trigger). The
`IF NOT EXISTS` and `OR IGNORE` clauses make it safe on a database that
somehow already has them.

- [ ] **Step 5: Write the accessor**

Create `internal/store/version.go`:

```go
package store

// ConfigVersion is the counter replicas poll. It is maintained by triggers on
// the replicated tables, so it moves for exactly the writes a replica needs to
// hear about and for no others.
func (s *Store) ConfigVersion() (int64, error) {
	var v int64
	err := s.db.QueryRow(`SELECT version FROM config_version WHERE id = 1`).Scan(&v)
	return v, err
}
```

- [ ] **Step 6: Run the tests**

```bash
CGO_ENABLED=0 go test ./internal/store/ -v
```

Expected: PASS, including `TestMigrationsAreIdempotent`.

- [ ] **Step 7: Commit**

```bash
git add internal/store/store.go internal/store/version.go internal/store/version_test.go
git commit -m "feat(store): count replicated writes in config_version

Triggers rather than Go call sites, so a write path added later cannot
forget to bump. The UPDATE OF column lists are the replicated settings
split, enforced in SQL instead of remembered."
```

---

### Task 2: The replicated settings split

**Files:**
- Create: `internal/settings/split.go`
- Test: `internal/settings/split_test.go`

**Interfaces:**
- Consumes: `store.Settings`.
- Produces: `func MergeReplicated(local, incoming store.Settings) store.Settings`.

- [ ] **Step 1: Write the failing test**

Create `internal/settings/split_test.go`:

```go
package settings

import (
	"testing"

	"github.com/yoshiofthewire/kydns-server/internal/store"
)

func TestMergeReplicatedTakesSharedKeys(t *testing.T) {
	local := store.Settings{PrivateDomain: "old.arpa", TTL: 60,
		Upstreams: []string{"tls://1.1.1.1:853"}}
	incoming := store.Settings{PrivateDomain: "home.arpa", TTL: 120,
		Upstreams: []string{"tls://9.9.9.9:853"}}

	got := MergeReplicated(local, incoming)

	if got.PrivateDomain != "home.arpa" {
		t.Errorf("PrivateDomain = %q, want home.arpa", got.PrivateDomain)
	}
	if got.TTL != 120 {
		t.Errorf("TTL = %d, want 120", got.TTL)
	}
	if len(got.Upstreams) != 1 || got.Upstreams[0] != "tls://9.9.9.9:853" {
		t.Errorf("Upstreams = %v, want [tls://9.9.9.9:853]", got.Upstreams)
	}
}

// The whole point of the split: a primary must never reach into a replica's
// lease file path or its query-logging privacy choice.
func TestMergeReplicatedKeepsNodeLocalKeys(t *testing.T) {
	local := store.Settings{
		DHCPLeaseFile: "/var/lib/misc/dnsmasq.leases", DiscoveryInterval: 15,
		LogQueries: true, LogClientIP: true,
	}
	incoming := store.Settings{
		DHCPLeaseFile: "/somewhere/on/the/primary", DiscoveryInterval: 300,
		LogQueries: false, LogClientIP: false,
	}

	got := MergeReplicated(local, incoming)

	if got.DHCPLeaseFile != "/var/lib/misc/dnsmasq.leases" {
		t.Errorf("DHCPLeaseFile = %q, want the local path", got.DHCPLeaseFile)
	}
	if got.DiscoveryInterval != 15 {
		t.Errorf("DiscoveryInterval = %d, want 15", got.DiscoveryInterval)
	}
	if !got.LogQueries {
		t.Error("LogQueries = false, want the local true")
	}
	if !got.LogClientIP {
		t.Error("LogClientIP = false, want the local true")
	}
}

// Slices must be copied, not aliased: a merged result that shares backing
// memory with the incoming document mutates when the document is reused.
func TestMergeReplicatedCopiesSlices(t *testing.T) {
	incoming := store.Settings{Upstreams: []string{"tls://1.1.1.1:853"}}
	got := MergeReplicated(store.Settings{}, incoming)
	incoming.Upstreams[0] = "udp://192.168.1.1:53"
	if got.Upstreams[0] != "tls://1.1.1.1:853" {
		t.Fatalf("Upstreams[0] = %q, want the value at merge time", got.Upstreams[0])
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

```bash
CGO_ENABLED=0 go test ./internal/settings/ -run MergeReplicated -v
```

Expected: FAIL — `undefined: MergeReplicated`.

- [ ] **Step 3: Implement**

Create `internal/settings/split.go`:

```go
package settings

import "github.com/yoshiofthewire/kydns-server/internal/store"

// MergeReplicated builds the settings a replica should store: shared policy
// from the primary, node-local keys kept from local. The node-local set is
// the same one the config_version triggers omit, and the two must stay in
// step — a key replicated here but not triggered there would never be
// delivered.
func MergeReplicated(local, incoming store.Settings) store.Settings {
	out := incoming
	out.ReverseZones = append([]string(nil), incoming.ReverseZones...)
	out.Upstreams = append([]string(nil), incoming.Upstreams...)
	out.AllowQuery = append([]string(nil), incoming.AllowQuery...)

	out.DHCPLeaseFile = local.DHCPLeaseFile
	out.DiscoveryInterval = local.DiscoveryInterval
	out.LogQueries = local.LogQueries
	out.LogClientIP = local.LogClientIP
	return out
}
```

- [ ] **Step 4: Run the tests**

```bash
CGO_ENABLED=0 go test ./internal/settings/ -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/settings/split.go internal/settings/split_test.go
git commit -m "feat(settings): merge a primary's settings without taking node-local keys"
```

---

### Task 3: The snapshot document

**Files:**
- Create: `internal/replica/doc.go`
- Test: `internal/replica/doc_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `replica.SchemaVersion` (const `int = 1`), `replica.Snapshot` struct with fields `SchemaVersion int`, `ConfigVersion int64`, `NodeID string`, `Config json.RawMessage`; `replica.VersionReply` struct with `SchemaVersion int`, `ConfigVersion int64`, `NodeID string`.

The `Config` field stays `json.RawMessage` deliberately: the transfer document
already has a settled shape in `internal/adminapi`, and re-declaring its DTOs
here would create two definitions that drift. The replica hands the raw bytes
back to the admin API's decoder in Task 5.

- [ ] **Step 1: Write the failing test**

Create `internal/replica/doc_test.go`:

```go
package replica

import (
	"encoding/json"
	"testing"
)

func TestSnapshotRoundTrips(t *testing.T) {
	in := Snapshot{
		SchemaVersion: SchemaVersion,
		ConfigVersion: 41,
		NodeID:        "abc123",
		Config:        json.RawMessage(`{"services":[]}`),
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out Snapshot
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if out.ConfigVersion != 41 || out.NodeID != "abc123" {
		t.Fatalf("round trip lost fields: %+v", out)
	}
	if string(out.Config) != `{"services":[]}` {
		t.Fatalf("Config = %s, want the original bytes", out.Config)
	}
}

func TestSchemaVersionIsOne(t *testing.T) {
	if SchemaVersion != 1 {
		t.Fatalf("SchemaVersion = %d; bumping it is a wire break and needs a "+
			"migration story, not a constant edit", SchemaVersion)
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

```bash
CGO_ENABLED=0 go test ./internal/replica/ -v
```

Expected: FAIL — no such package.

- [ ] **Step 3: Implement**

Create `internal/replica/doc.go`:

```go
// Package replica implements linked-server replication: one primary that
// serves configuration snapshots, and replicas that pull them.
package replica

import "encoding/json"

// SchemaVersion is the replication wire format. A peer on a different version
// is refused rather than coerced: a replica must never guess at a document a
// newer primary wrote.
const SchemaVersion = 1

// VersionReply answers the cheap poll. It is deliberately tiny — a replica
// asks for it every five seconds and almost always learns nothing changed.
type VersionReply struct {
	SchemaVersion int    `json:"schema_version"`
	ConfigVersion int64  `json:"config_version"`
	NodeID        string `json:"node_id"`
}

// Snapshot is the whole replicated configuration plus the version it was read
// at. Both are read in one transaction, so the version can never describe a
// configuration other than the one shipped with it.
type Snapshot struct {
	SchemaVersion int             `json:"schema_version"`
	ConfigVersion int64           `json:"config_version"`
	NodeID        string          `json:"node_id"`
	Config        json.RawMessage `json:"config"`
}
```

- [ ] **Step 4: Run the tests**

```bash
CGO_ENABLED=0 go test ./internal/replica/ -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/replica/
git commit -m "feat(replica): the replication wire document"
```

---

### Task 4: Node identity

**Files:**
- Create: `internal/replica/identity.go`
- Test: `internal/replica/identity_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `type Identity struct { PrivateKey ed25519.PrivateKey; PublicKey ed25519.PublicKey; NodeID string }` and `func LoadOrCreateIdentity(dataDir string) (*Identity, error)`, plus `func Fingerprint(pub ed25519.PublicKey) string`.

- [ ] **Step 1: Write the failing tests**

Create `internal/replica/identity_test.go`:

```go
package replica

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLoadOrCreateIdentityIsStable(t *testing.T) {
	dir := t.TempDir()
	first, err := LoadOrCreateIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreateIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	if first.NodeID != second.NodeID {
		t.Fatalf("NodeID changed across loads: %q then %q", first.NodeID, second.NodeID)
	}
	if first.NodeID == "" {
		t.Fatal("NodeID is empty")
	}
}

func TestDistinctDirsGetDistinctIdentities(t *testing.T) {
	a, err := LoadOrCreateIdentity(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadOrCreateIdentity(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if a.NodeID == b.NodeID {
		t.Fatal("two nodes share a NodeID")
	}
}

// The private key is the node's whole identity. A world-readable key means any
// local account can impersonate this node to its peers.
func TestPrivateKeyIsNotReadableByOthers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes only")
	}
	dir := t.TempDir()
	if _, err := LoadOrCreateIdentity(dir); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dir, "node_key"))
	if err != nil {
		t.Fatal(err)
	}
	if mode := fi.Mode().Perm(); mode != 0o600 {
		t.Fatalf("node_key mode = %#o, want 0600", mode)
	}
}

func TestFingerprintIsDeterministic(t *testing.T) {
	id, err := LoadOrCreateIdentity(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if got := Fingerprint(id.PublicKey); got != id.NodeID {
		t.Fatalf("Fingerprint() = %q, NodeID = %q; they must agree", got, id.NodeID)
	}
}

func TestCorruptKeyIsAnErrorNotANewIdentity(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadOrCreateIdentity(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "node_key"), []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateIdentity(dir); err == nil {
		t.Fatal("a corrupt key silently minted a new identity; every peer would " +
			"refuse this node and the operator would have no idea why")
	}
}
```

- [ ] **Step 2: Run to verify failure**

```bash
CGO_ENABLED=0 go test ./internal/replica/ -run Identity -v
```

Expected: FAIL — `undefined: LoadOrCreateIdentity`.

- [ ] **Step 3: Implement**

Create `internal/replica/identity.go`:

```go
package replica

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const keyFile = "node_key"

// Identity is this node's long-lived keypair. The node ID is the public key's
// fingerprint, so identity is the key itself rather than a name two operators
// could pick the same way.
type Identity struct {
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
	NodeID     string
}

// Fingerprint is the peer identifier shown to operators and pinned at pairing.
func Fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

// LoadOrCreateIdentity reads data_dir/node_key, generating it on first use. A
// key that exists but cannot be parsed is an error: silently replacing it
// would change this node's identity and make every paired peer refuse it.
func LoadOrCreateIdentity(dataDir string) (*Identity, error) {
	path := filepath.Join(dataDir, keyFile)
	seed, err := os.ReadFile(path)
	switch {
	case err == nil:
		if len(seed) != ed25519.SeedSize {
			return nil, fmt.Errorf("%s: want %d bytes, found %d", path, ed25519.SeedSize, len(seed))
		}
	case errors.Is(err, os.ErrNotExist):
		seed = make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, seed, 0o600); err != nil {
			return nil, fmt.Errorf("write %s: %w", path, err)
		}
	default:
		return nil, err
	}

	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return &Identity{PrivateKey: priv, PublicKey: pub, NodeID: Fingerprint(pub)}, nil
}
```

- [ ] **Step 4: Run the tests**

```bash
CGO_ENABLED=0 go test ./internal/replica/ -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/replica/identity.go internal/replica/identity_test.go
git commit -m "feat(replica): a node is its Ed25519 key"
```

---

### Task 5: Transactional snapshot apply

**Files:**
- Modify: `internal/store/store.go` (add `ApplySnapshot`)
- Test: `internal/store/apply_test.go`

**Interfaces:**
- Consumes: `store.View`, `store.Service`, `store.Record`, `store.Settings`, `store.BlacklistSettings`, `store.BlacklistList`, `store.BlacklistRule`.
- Produces:

```go
type SnapshotInput struct {
	Views    []View
	Services []Service
	Records  []Record
	Settings Settings
	Blacklist BlacklistSettings
	Lists    []BlacklistList
	Rules    []BlacklistRule
}

func (s *Store) ApplySnapshot(in SnapshotInput) error
```

This is the deviation named at the top of the plan. `adminapi.importDoc` does
registry, blacklist, and settings as three sequential calls; a failure between
them leaves a half-applied configuration. A replica must never do that, so the
whole apply goes in one transaction here.

Before writing, read `internal/store/store.go` for `ReplaceAll` and
`internal/store/blacklist.go` for the blacklist writers, and reuse their
`tx`-taking internal helpers (`putView`, and whatever `ReplaceAll` calls). If a
writer has no `tx`-taking form yet, extract one the same way `PutView` and
`putView` are split — do not open a second transaction inside this one, which
deadlocks a store limited to a single connection.

- [ ] **Step 1: Write the failing tests**

Create `internal/store/apply_test.go`:

```go
package store

import "testing"

func baseSettings() Settings {
	return Settings{PrivateDomain: "home.arpa", TTL: 60, CacheMinTTL: 5,
		CacheMaxTTL: 3600, NegativeMaxTTL: 300, CacheEntries: 10000,
		DiscoveryInterval: 30, HealthInterval: 30, HealthTimeout: 5, HealthWorkers: 8}
}

func TestApplySnapshotReplacesRegistry(t *testing.T) {
	s := open(t)
	if _, err := s.PutService(Service{Name: "old"}); err != nil {
		t.Fatal(err)
	}
	err := s.ApplySnapshot(SnapshotInput{
		Services: []Service{{Name: "new"}},
		Settings: baseSettings(),
	})
	if err != nil {
		t.Fatal(err)
	}
	svcs, err := s.Services()
	if err != nil {
		t.Fatal(err)
	}
	if len(svcs) != 1 || svcs[0].Name != "new" {
		t.Fatalf("Services() = %+v, want exactly [new]", svcs)
	}
}

// The spec's central failure promise: a bad snapshot degrades a replica to
// stale, never to broken.
func TestApplySnapshotRollsBackEverythingOnFailure(t *testing.T) {
	s := open(t)
	if _, err := s.PutService(Service{Name: "keeper"}); err != nil {
		t.Fatal(err)
	}
	before := baseSettings()
	before.TTL = 60
	if err := s.PutSettings(before); err != nil {
		t.Fatal(err)
	}

	bad := baseSettings()
	bad.TTL = 999
	// Two rules for one domain violate the UNIQUE index, and the violation is
	// reached only after the services and settings writes above it.
	err := s.ApplySnapshot(SnapshotInput{
		Services: []Service{{Name: "replacement"}},
		Settings: bad,
		Rules: []BlacklistRule{
			{Kind: "deny", Domain: "ads.example"},
			{Kind: "allow", Domain: "ads.example"},
		},
	})
	if err == nil {
		t.Fatal("ApplySnapshot() accepted two rules for one domain")
	}

	svcs, err := s.Services()
	if err != nil {
		t.Fatal(err)
	}
	if len(svcs) != 1 || svcs[0].Name != "keeper" {
		t.Fatalf("Services() = %+v after a failed apply, want the untouched [keeper]", svcs)
	}
	got, _, err := s.Settings()
	if err != nil {
		t.Fatal(err)
	}
	if got.TTL != 60 {
		t.Fatalf("TTL = %d after a failed apply, want the untouched 60", got.TTL)
	}
}

// Tokens and the admin account are node-local. A snapshot must not reach them.
func TestApplySnapshotLeavesTokensAndAdminAlone(t *testing.T) {
	s := open(t)
	if _, err := s.PutToken(Token{Label: "cli", Hash: "hash-1"}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutAdminPassword("argon2-hash"); err != nil {
		t.Fatal(err)
	}
	if err := s.ApplySnapshot(SnapshotInput{Settings: baseSettings()}); err != nil {
		t.Fatal(err)
	}
	toks, err := s.Tokens()
	if err != nil {
		t.Fatal(err)
	}
	if len(toks) != 1 {
		t.Fatalf("Tokens() = %d after apply, want 1", len(toks))
	}
	hash, ok, err := s.AdminPassword()
	if err != nil {
		t.Fatal(err)
	}
	if !ok || hash != "argon2-hash" {
		t.Fatalf("AdminPassword() = %q ok=%v, want the untouched hash", hash, ok)
	}
}

// A list body is node-local: each node downloads its own. Applying a snapshot
// must not blank out a body this node already has.
func TestApplySnapshotKeepsLocalListBodies(t *testing.T) {
	s := open(t)
	l, err := s.PutBlacklistList(BlacklistList{Name: "steven",
		URL: "https://example.test/hosts", Format: "hosts"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SaveBlacklistSnapshot(l.ID, []string{"ads.example"}, "etag-1", ""); err != nil {
		t.Fatal(err)
	}
	err = s.ApplySnapshot(SnapshotInput{
		Settings: baseSettings(),
		Lists: []BlacklistList{{Name: "steven",
			URL: "https://example.test/hosts", Format: "hosts", Enabled: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	lists, err := s.BlacklistLists()
	if err != nil {
		t.Fatal(err)
	}
	if len(lists) != 1 {
		t.Fatalf("BlacklistLists() = %d, want 1", len(lists))
	}
	body, err := s.BlacklistSnapshot(lists[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) != 1 || body[0] != "ads.example" {
		t.Fatalf("list body = %v after apply, want the locally downloaded body", body)
	}
}
```

Method names above (`PutAdminPassword`, `AdminPassword`, `Tokens`,
`BlacklistLists`, `BlacklistSnapshot`, `SaveBlacklistSnapshot`) must be checked
against the real store first with
`grep -n "func (s \*Store)" internal/store/*.go` and corrected to match. Do not
add wrappers to make the test compile.

- [ ] **Step 2: Run to verify failure**

```bash
CGO_ENABLED=0 go test ./internal/store/ -run ApplySnapshot -v
```

Expected: FAIL — `s.ApplySnapshot undefined`.

- [ ] **Step 3: Implement `ApplySnapshot`**

In `internal/store/store.go`, one `Begin`, every write through `tx`-taking
helpers, one `Commit`, with `defer tx.Rollback()`. Match a list to its existing
row by `name` so the local body survives; update the definition columns only,
insert lists that are new, and delete lists absent from the snapshot.

Sketch of the shape — fill in using the real helper names found in Step 1:

```go
// ApplySnapshot replaces all replicated state in one transaction. A replica
// applying a bad document must be left exactly as it was, so nothing here is
// allowed to commit independently.
func (s *Store) ApplySnapshot(in SnapshotInput) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if err := replaceAll(tx, in.Views, in.Services, in.Records); err != nil {
		return err
	}
	if err := replaceBlacklistDefinitions(tx, in.Blacklist, in.Lists, in.Rules); err != nil {
		return err
	}
	if err := putSettings(tx, in.Settings); err != nil {
		return err
	}
	return tx.Commit()
}
```

- [ ] **Step 4: Run the tests**

```bash
CGO_ENABLED=0 go test ./internal/store/ -v
```

Expected: PASS, with the existing store tests still green.

- [ ] **Step 5: Commit**

```bash
git add internal/store/store.go internal/store/blacklist.go internal/store/apply_test.go
git commit -m "feat(store): apply a replication snapshot in one transaction

A half-applied snapshot would leave a replica serving a configuration that
never existed on the primary. One transaction, or nothing."
```

---

### Task 6: Choose the PAKE — decision gate

**Files:**
- Create: `docs/superpowers/specs/2026-08-13-kydns-pake-selection.md`
- Modify: `go.mod`, `go.sum`
- Test: `internal/replica/pake_smoke_test.go`

**Interfaces:**
- Produces: a chosen package, and the two-message exchange shape Task 7 builds on.

**This task can block the plan.** Neither the standard library nor
`golang.org/x/crypto` provides a PAKE — verified: `x/crypto` has no `spake2`
or `cpace` package. If no candidate clears review, **stop and report**. Do not
substitute a bearer token over TLS; that reopens the man-in-the-middle the
design exists to close, and the choice belongs to the human.

- [ ] **Step 1: Evaluate candidates**

Look for a Go implementation of a balanced PAKE — CPace (RFC 9383 family) or
SPAKE2. For each candidate record: import path, licence, last release, whether
it has had outside cryptographic review, whether it pins to a maintained curve
implementation, and its transitive dependency count.

Reject any candidate that is unmaintained, has no review, or drags in a large
dependency tree. This is the only dependency this feature adds and it is
carrying the whole trust boundary.

- [ ] **Step 2: Write the decision up**

Create `docs/superpowers/specs/2026-08-13-kydns-pake-selection.md` recording
the candidates, the criteria above for each, the choice, and the reason. If the
answer is "none qualify," write that and stop here.

- [ ] **Step 3: Add the dependency**

```bash
go get <chosen/module>
go mod tidy
```

- [ ] **Step 4: Write a smoke test proving the primitive does what pairing needs**

Create `internal/replica/pake_smoke_test.go` asserting, against the chosen
library's own API:

1. Two parties given the same low-entropy password derive an identical shared
   key.
2. Two parties given different passwords do **not** derive an identical shared
   key, and the mismatch is detectable by the protocol rather than only by a
   later failure.

- [ ] **Step 5: Run it**

```bash
CGO_ENABLED=0 go test ./internal/replica/ -run PAKE -v
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add go.mod go.sum internal/replica/pake_smoke_test.go docs/superpowers/specs/2026-08-13-kydns-pake-selection.md
git commit -m "build: select a PAKE for peer pairing

Recorded the candidates and the criteria. The pairing code is low-entropy
and typed by a human, so it can never be sent as a bearer token."
```

---

### Task 7: Peer records and pairing

**Files:**
- Modify: `internal/store/store.go` (peers table, in `schema` and a new migration entry)
- Create: `internal/store/peer.go`, `internal/replica/pairing.go`
- Test: `internal/store/peer_test.go`, `internal/replica/pairing_test.go`

**Interfaces:**
- Consumes: `replica.Identity`, `replica.Fingerprint`, the PAKE from Task 6.
- Produces:

```go
// store
type Peer struct {
	NodeID      string // fingerprint, primary key
	Label       string
	Address     string
	PairedAt    int64
	LastSyncAt  int64
	LastVersion int64
}
func (s *Store) PutPeer(p Peer) error
func (s *Store) Peers() ([]Peer, error)
func (s *Store) Peer(nodeID string) (Peer, error) // ErrNotFound when absent
func (s *Store) DeletePeer(nodeID string) error
func (s *Store) TouchPeer(nodeID string, syncedAt, version int64) error

// replica
func NewPairingCode() (string, error)
type Invite struct { Code string; ExpiresAt time.Time }
type InviteBook struct{ /* unexported */ }
func NewInviteBook(ttl time.Duration, now func() time.Time) *InviteBook
func (b *InviteBook) Mint() (Invite, error)
func (b *InviteBook) Redeem(code string) bool
```

The peers table is node-local: it carries no `config_version` trigger, because
each node's peer list is its own.

`InviteBook` takes a `now` function so expiry is tested without sleeping.

- [ ] **Step 1: Write the failing tests**

Create `internal/replica/pairing_test.go`:

```go
package replica

import (
	"testing"
	"time"
)

func TestPairingCodeIsUnguessable(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 500; i++ {
		c, err := NewPairingCode()
		if err != nil {
			t.Fatal(err)
		}
		if len(c) < 12 {
			t.Fatalf("code %q is %d characters; too short to resist "+
				"online guessing inside its ten-minute window", c, len(c))
		}
		if seen[c] {
			t.Fatalf("NewPairingCode() repeated %q within 500 draws", c)
		}
		seen[c] = true
	}
}

func TestInviteRedeemsOnce(t *testing.T) {
	now := time.Now()
	b := NewInviteBook(10*time.Minute, func() time.Time { return now })
	inv, err := b.Mint()
	if err != nil {
		t.Fatal(err)
	}
	if !b.Redeem(inv.Code) {
		t.Fatal("Redeem() rejected a fresh code")
	}
	if b.Redeem(inv.Code) {
		t.Fatal("Redeem() accepted a spent code; a captured code would pair a " +
			"second, unauthorized node")
	}
}

func TestInviteExpires(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	b := NewInviteBook(10*time.Minute, clock)
	inv, err := b.Mint()
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(11 * time.Minute)
	if b.Redeem(inv.Code) {
		t.Fatal("Redeem() accepted an expired code")
	}
}

func TestRedeemRejectsUnknownCode(t *testing.T) {
	b := NewInviteBook(10*time.Minute, time.Now)
	if b.Redeem("not-a-real-code") {
		t.Fatal("Redeem() accepted a code that was never minted")
	}
}
```

Create `internal/store/peer_test.go`:

```go
package store

import (
	"errors"
	"testing"
)

func TestPeerRoundTrip(t *testing.T) {
	s := open(t)
	p := Peer{NodeID: "fp-1", Label: "pi", Address: "192.168.1.9:8443", PairedAt: 100}
	if err := s.PutPeer(p); err != nil {
		t.Fatal(err)
	}
	got, err := s.Peer("fp-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Label != "pi" || got.Address != "192.168.1.9:8443" {
		t.Fatalf("Peer() = %+v, want the stored values", got)
	}
}

func TestPeerNotFound(t *testing.T) {
	s := open(t)
	if _, err := s.Peer("nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Peer() error = %v, want ErrNotFound", err)
	}
}

func TestDeletePeerRemovesIt(t *testing.T) {
	s := open(t)
	if err := s.PutPeer(Peer{NodeID: "fp-1"}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeletePeer("fp-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Peer("fp-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Peer() error = %v after delete, want ErrNotFound", err)
	}
}

// The peer list is this node's own. Replicating it would make a primary
// rewrite its replicas' trust anchors.
func TestPeerWriteDoesNotBumpConfigVersion(t *testing.T) {
	s := open(t)
	before, err := s.ConfigVersion()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutPeer(Peer{NodeID: "fp-1"}); err != nil {
		t.Fatal(err)
	}
	after, err := s.ConfigVersion()
	if err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("ConfigVersion() = %d after a peer write, want %d", after, before)
	}
}
```

- [ ] **Step 2: Run to verify failure**

```bash
CGO_ENABLED=0 go test ./internal/store/ -run Peer -v
CGO_ENABLED=0 go test ./internal/replica/ -run "Pairing|Invite|Redeem" -v
```

Expected: FAIL on undefined symbols in both.

- [ ] **Step 3: Add the peers table**

In `internal/store/store.go`, append to `schema` and add the identical
statement as a new `migrations` entry:

```sql
CREATE TABLE IF NOT EXISTS peers (
  node_id      TEXT PRIMARY KEY,
  label        TEXT NOT NULL DEFAULT '',
  address      TEXT NOT NULL DEFAULT '',
  paired_at    INTEGER NOT NULL DEFAULT 0,
  last_sync_at INTEGER NOT NULL DEFAULT 0,
  last_version INTEGER NOT NULL DEFAULT 0
);
```

No `config_version` trigger on this table, deliberately.

- [ ] **Step 4: Implement the store methods**

Create `internal/store/peer.go` with `PutPeer` (upsert on `node_id`), `Peers`
(ordered by `label` then `node_id`), `Peer` (returning `ErrNotFound`),
`DeletePeer`, and `TouchPeer`. Follow the SQL style already in
`internal/store/blacklist.go`.

- [ ] **Step 5: Implement pairing codes**

Create `internal/replica/pairing.go`:

```go
package replica

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"strings"
	"sync"
	"time"
)

// codeAlphabet is Crockford-ish base32 without padding: an operator reads this
// off one screen and types it into another, so I and O and their digit
// lookalikes stay out.
var codeEncoding = base32.NewEncoding("ABCDEFGHJKMNPQRSTVWXYZ0123456789").WithPadding(base32.NoPadding)

// NewPairingCode returns 80 bits of entropy. That is far more than a PAKE
// needs, and it costs the operator one extra line to type once in a node's
// lifetime.
func NewPairingCode() (string, error) {
	b := make([]byte, 10)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return codeEncoding.EncodeToString(b), nil
}

// Invite is one outstanding pairing code.
type Invite struct {
	Code      string
	ExpiresAt time.Time
}

// InviteBook holds unredeemed codes in memory only. A restart cancels every
// outstanding invite, which is the right default: an invite is something an
// operator is using right now.
type InviteBook struct {
	mu  sync.Mutex
	ttl time.Duration
	now func() time.Time
	out map[string]time.Time
}

func NewInviteBook(ttl time.Duration, now func() time.Time) *InviteBook {
	return &InviteBook{ttl: ttl, now: now, out: map[string]time.Time{}}
}

func (b *InviteBook) Mint() (Invite, error) {
	code, err := NewPairingCode()
	if err != nil {
		return Invite{}, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	exp := b.now().Add(b.ttl)
	b.out[code] = exp
	return Invite{Code: code, ExpiresAt: exp}, nil
}

// Redeem consumes a code. It compares in constant time and against every
// outstanding entry, so the time it takes does not reveal how much of a guess
// was right.
func (b *InviteBook) Redeem(code string) bool {
	code = strings.ToUpper(strings.TrimSpace(code))
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	found := false
	for c, exp := range b.out {
		if now.After(exp) {
			delete(b.out, c)
			continue
		}
		if subtle.ConstantTimeCompare([]byte(c), []byte(code)) == 1 {
			found = true
			delete(b.out, c)
		}
	}
	return found
}
```

- [ ] **Step 6: Run the tests**

```bash
CGO_ENABLED=0 go test ./internal/store/ ./internal/replica/ -v
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/store/store.go internal/store/peer.go internal/store/peer_test.go internal/replica/pairing.go internal/replica/pairing_test.go
git commit -m "feat(store,replica): peer records and single-use pairing codes

Codes live in memory, so a restart cancels every outstanding invite.
The peers table carries no config_version trigger: a node's trust
anchors are its own and must never arrive from a peer."
```

---

### Task 8: The pairing exchange

**Files:**
- Create: `internal/replica/handshake.go`
- Test: `internal/replica/handshake_test.go`

**Interfaces:**
- Consumes: `Identity`, `InviteBook`, `Fingerprint`, the PAKE from Task 6.
- Produces:

```go
// PairAsPrimary runs the primary side over conn, returning the peer's
// fingerprint on success.
func PairAsPrimary(conn net.Conn, id *Identity, book *InviteBook) (peerFingerprint string, err error)

// PairAsReplica runs the replica side over conn, returning the primary's
// fingerprint on success.
func PairAsReplica(conn net.Conn, id *Identity, code string) (primaryFingerprint string, err error)
```

Both sides derive a shared key from the code with the PAKE, then each signs a
transcript hash with its Ed25519 key and sends its public key. The signature
binds the key to the PAKE session, so an observer who later guesses the code
still cannot substitute a key. Only after both signatures verify does either
side return a fingerprint.

- [ ] **Step 1: Write the failing tests**

Create `internal/replica/handshake_test.go`:

```go
package replica

import (
	"net"
	"testing"
	"time"
)

func pairOver(t *testing.T, code string, book *InviteBook) (string, string, error, error) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })

	pid, err := LoadOrCreateIdentity(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	rid, err := LoadOrCreateIdentity(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	type res struct {
		fp  string
		err error
	}
	pc := make(chan res, 1)
	go func() {
		fp, err := PairAsPrimary(a, pid, book)
		pc <- res{fp, err}
	}()
	rfp, rerr := PairAsReplica(b, rid, code)
	p := <-pc
	return p.fp, rfp, p.err, rerr
}

func TestPairingSucceedsAndPinsBothWays(t *testing.T) {
	book := NewInviteBook(10*time.Minute, time.Now)
	inv, err := book.Mint()
	if err != nil {
		t.Fatal(err)
	}
	pfp, rfp, perr, rerr := pairOver(t, inv.Code, book)
	if perr != nil || rerr != nil {
		t.Fatalf("pairing failed: primary=%v replica=%v", perr, rerr)
	}
	if pfp == "" || rfp == "" {
		t.Fatal("pairing returned an empty fingerprint")
	}
	if pfp == rfp {
		t.Fatal("both sides returned the same fingerprint; each must return " +
			"the OTHER node's")
	}
}

func TestPairingRejectsWrongCode(t *testing.T) {
	book := NewInviteBook(10*time.Minute, time.Now)
	if _, err := book.Mint(); err != nil {
		t.Fatal(err)
	}
	_, _, perr, rerr := pairOver(t, "WRONGCODE123", book)
	if perr == nil && rerr == nil {
		t.Fatal("pairing succeeded with a code that was never minted")
	}
}

func TestPairingRejectsSpentCode(t *testing.T) {
	book := NewInviteBook(10*time.Minute, time.Now)
	inv, err := book.Mint()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, perr, rerr := pairOver(t, inv.Code, book); perr != nil || rerr != nil {
		t.Fatalf("first pairing failed: %v %v", perr, rerr)
	}
	_, _, perr, rerr := pairOver(t, inv.Code, book)
	if perr == nil && rerr == nil {
		t.Fatal("the same code paired a second node")
	}
}

func TestPairingRejectsExpiredCode(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	book := NewInviteBook(10*time.Minute, clock)
	inv, err := book.Mint()
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(11 * time.Minute)
	_, _, perr, rerr := pairOver(t, inv.Code, book)
	if perr == nil && rerr == nil {
		t.Fatal("an expired code still paired")
	}
}

// The property the PAKE exists for. An attacker who records the entire
// exchange must not learn the code, so they cannot pair later or replay it.
func TestObserverCannotRecoverTheCodeFromTheTranscript(t *testing.T) {
	book := NewInviteBook(10*time.Minute, time.Now)
	inv, err := book.Mint()
	if err != nil {
		t.Fatal(err)
	}

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	tapped, transcript := tap(a)

	pid, _ := LoadOrCreateIdentity(t.TempDir())
	rid, _ := LoadOrCreateIdentity(t.TempDir())
	go func() { _, _ = PairAsPrimary(tapped, pid, book) }()
	if _, err := PairAsReplica(b, rid, inv.Code); err != nil {
		t.Fatal(err)
	}

	if bytesContains(transcript.Bytes(), []byte(inv.Code)) {
		t.Fatal("the pairing code appears verbatim in the wire transcript")
	}
}
```

Write the `tap` helper (an `io.ReadWriter` wrapper recording both directions
into a `bytes.Buffer`) and `bytesContains` (`bytes.Contains`) in the test file.

Note what this last test does and does not prove: it shows the code is not
transmitted in the clear, which is the mistake worth guarding against in this
codebase. It is not a proof of the PAKE's security — that comes from the
reviewed implementation chosen in Task 6, and the note belongs in a comment
above the test.

- [ ] **Step 2: Run to verify failure**

```bash
CGO_ENABLED=0 go test ./internal/replica/ -run Pairing -v
```

Expected: FAIL — `undefined: PairAsPrimary`.

- [ ] **Step 3: Implement the handshake**

Create `internal/replica/handshake.go`. Structure:

1. Length-prefixed JSON messages over `conn`, with a read deadline of 10
   seconds and a maximum message size of 64 KiB, so a stalled or hostile peer
   cannot hold a goroutine or exhaust memory.
2. Replica sends its PAKE message; primary redeems the code from the book and
   replies with its own PAKE message. A redeem failure still completes the
   round trip with a dummy message before erroring, so failure timing does not
   distinguish "no such code" from "wrong code".
3. Both derive the shared key.
4. Each sends `{public_key, signature}` where the signature is over
   `sha256("kydns-pair-v1" || sharedKey || sortedConcat(bothPublicKeys))`.
5. Each verifies the other's signature; on success return
   `Fingerprint(theirPub)`.

- [ ] **Step 4: Run the tests**

```bash
CGO_ENABLED=0 go test ./internal/replica/ -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/replica/handshake.go internal/replica/handshake_test.go
git commit -m "feat(replica): pair two nodes from a typed code

The code is a PAKE secret, never a bearer token: before pinning there is
nothing to authenticate a certificate against, so a transmitted code goes
straight to whoever answered the connection."
```

---

### Task 9: TLS transport with pinned peers

**Files:**
- Create: `internal/replica/transport.go`, `internal/replica/server.go`
- Test: `internal/replica/transport_test.go`, `internal/replica/server_test.go`

**Interfaces:**
- Consumes: `Identity`, `store.Peer`, `Snapshot`, `VersionReply`.
- Produces:

```go
type PeerStore interface {
	Peer(nodeID string) (store.Peer, error)
	Peers() ([]store.Peer, error)
	TouchPeer(nodeID string, syncedAt, version int64) error
}

type Source interface {
	Version() (VersionReply, error)
	Snapshot() (Snapshot, error)
}

// NewServer serves /replica/version and /replica/snapshot over TLS,
// accepting only peers whose fingerprint is in peers.
func NewServer(id *Identity, peers PeerStore, src Source, book *InviteBook) *Server
func (s *Server) Serve(l net.Listener) error
func (s *Server) Close() error

// Dial connects to a primary and verifies its fingerprint matches want.
func Dial(ctx context.Context, address string, id *Identity, want string) (*Client, error)
func (c *Client) Version(ctx context.Context) (VersionReply, error)
func (c *Client) Snapshot(ctx context.Context) (Snapshot, error)
func (c *Client) Close() error
```

Both sides use a self-signed certificate carrying the node's Ed25519 key, with
`InsecureSkipVerify: true` and a `VerifyPeerCertificate` that checks the
fingerprint against the pinned set. That is not a weakening: there is no CA in
this design, and the pin is a strictly stronger check than name validation.
Say so in a comment, because `InsecureSkipVerify` will otherwise read as a bug
to every future reviewer.

- [ ] **Step 1: Write the failing tests**

Create `internal/replica/transport_test.go` covering:

```go
// A peer that is not pinned gets no data. This is the whole access control.
func TestServerRefusesUnpinnedPeer(t *testing.T)

// After pairing, a peer whose key changed is an impostor or a reinstalled
// node. Either way it is refused, with no prompt and no trust-on-next-use.
func TestClientRefusesPrimaryWithWrongFingerprint(t *testing.T)

// A pinned peer reads both endpoints.
func TestPinnedPeerReadsVersionAndSnapshot(t *testing.T)

// Removing a peer takes effect on its next request.
func TestRemovedPeerIsRefusedOnNextRequest(t *testing.T)

// Replication is read-only. A write method must not be a way in.
func TestServerRejectsNonGETMethods(t *testing.T)

// A version reply must never describe a different configuration than the
// snapshot shipped with it.
func TestSnapshotVersionMatchesItsBody(t *testing.T)
```

Fill each in against the interfaces above, using `httptest`-style in-process
listeners (`net.Listen("tcp", "127.0.0.1:0")`) and a fake `Source`.

- [ ] **Step 2: Run to verify failure**

```bash
CGO_ENABLED=0 go test ./internal/replica/ -run "Server|Client|Pinned|Snapshot" -v
```

Expected: FAIL — undefined symbols.

- [ ] **Step 3: Implement the certificate and pin check**

Create `internal/replica/transport.go` with:

- `selfSignedCert(id *Identity) (tls.Certificate, error)` — an x509
  certificate with the node's Ed25519 key as both subject and signer, a
  100-year validity (there is no renewal path and the pin is what is checked),
  and the node ID as the common name.
- `pinnedTLSConfig(id *Identity, allowed func(fp string) bool) *tls.Config` —
  `MinVersion: tls.VersionTLS13`, `InsecureSkipVerify: true`, and a
  `VerifyPeerCertificate` that parses the leaf, extracts the Ed25519 public
  key, computes `Fingerprint`, and calls `allowed`. Reject anything that is not
  an Ed25519 key.

- [ ] **Step 4: Implement the server and client**

Create `internal/replica/server.go`: an `http.Server` over the pinned TLS
config, `GET /replica/version` and `GET /replica/snapshot` only, every other
method answered `405`, and `TouchPeer` called on each successful request so a
primary can report last-seen times.

Add `Dial`, `Version`, `Snapshot`, and `Close` to the client side, each taking
a `context.Context` and using a 10-second timeout.

- [ ] **Step 5: Run the tests**

```bash
CGO_ENABLED=0 go test ./internal/replica/ -v
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/replica/transport.go internal/replica/server.go internal/replica/transport_test.go internal/replica/server_test.go
git commit -m "feat(replica): TLS between peers, authenticated by pinned key

InsecureSkipVerify with a fingerprint check is not a weakening: there is
no CA here, and the pin is a stricter check than name validation."
```

---

### Task 10: The pull loop

**Files:**
- Create: `internal/replica/puller.go`
- Modify: `internal/store/store.go` (add `replica_state` table to `schema` and `migrations`), `internal/store/peer.go`
- Test: `internal/replica/puller_test.go`

**Interfaces:**
- Consumes: `Client`, `store.SnapshotInput`, `settings.MergeReplicated`.
- Produces:

```go
type Applier interface {
	// Apply decodes a snapshot's Config and writes it in one transaction.
	Apply(cfg json.RawMessage) error
}

type Puller struct{ /* unexported */ }

func NewPuller(dial func(context.Context) (*Client, error), ap Applier,
	state StateStore, interval, ceiling time.Duration, now func() time.Time) *Puller

func (p *Puller) Run(ctx context.Context)

// Status is what the operator surface in part 2 renders.
type Status struct {
	PrimaryNodeID string
	LastSyncAt    time.Time
	LastVersion   int64
	LastError     string
	Stale         bool
}
func (p *Puller) Status() Status
```

`StateStore` persists `last_version` so a restarted replica does not re-pull a
configuration it already has:

```go
type StateStore interface {
	ReplicaState() (primaryNodeID string, version int64, err error)
	SetReplicaState(primaryNodeID string, version int64) error
}
```

- [ ] **Step 1: Write the failing tests**

Create `internal/replica/puller_test.go` covering, with a fake client and a
fake applier:

```go
// The common case: an unchanged version does not fetch a snapshot.
func TestUnchangedVersionDoesNotFetch(t *testing.T)

// A changed version fetches and applies exactly once.
func TestChangedVersionAppliesOnce(t *testing.T)

// The spec's failure promise, at the loop level.
func TestFailedApplyKeepsTheOldVersionAndRetries(t *testing.T)

// A newer primary must not have its document guessed at.
func TestSchemaVersionMismatchIsRefusedAndNamesBothVersions(t *testing.T)

// An unreachable primary is not an outage.
func TestUnreachablePrimaryBacksOffAndGoesStale(t *testing.T)

// After the staleness threshold the operator surface must be able to say so.
func TestStatusReportsStaleAfterSixtySeconds(t *testing.T)

// A restarted replica already holding the primary's version does not re-apply.
func TestPersistedVersionSurvivesRestart(t *testing.T)
```

Drive time with the injected `now` and a manually-stepped ticker rather than
sleeping. No test in this file may call `time.Sleep`.

- [ ] **Step 2: Run to verify failure**

```bash
CGO_ENABLED=0 go test ./internal/replica/ -run Puller -v
```

Expected: FAIL — `undefined: NewPuller`.

- [ ] **Step 3: Add `replica_state`**

Append to `schema` and add as a new `migrations` entry:

```sql
CREATE TABLE IF NOT EXISTS replica_state (
  id              INTEGER PRIMARY KEY CHECK (id = 1),
  primary_node_id TEXT NOT NULL DEFAULT '',
  last_version    INTEGER NOT NULL DEFAULT 0
);
INSERT OR IGNORE INTO replica_state(id) VALUES(1);
```

No `config_version` trigger: this is node-local bookkeeping.

Add `ReplicaState` and `SetReplicaState` to `internal/store/peer.go`.

- [ ] **Step 4: Implement the puller**

Create `internal/replica/puller.go`. The loop:

1. Tick every `interval` (5s).
2. `Version(ctx)`. On error: record it, back off with doubling capped at
   `ceiling` (60s), continue. Never exit the loop on a transport error — an
   unreachable primary is an expected state, not a fatal one.
3. On success reset the backoff. If `reply.SchemaVersion != SchemaVersion`,
   record an error naming both versions and continue without fetching.
4. If `reply.ConfigVersion == p.lastVersion`, record the sync time and continue.
5. `Snapshot(ctx)`, then `ap.Apply(snap.Config)`. On error record it and leave
   `lastVersion` untouched so the next tick retries.
6. On success `SetReplicaState` and record the sync time.

`Status().Stale` is `now().Sub(lastSyncAt) > 60s`.

- [ ] **Step 5: Run the tests**

```bash
CGO_ENABLED=0 go test ./internal/replica/ -v
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/replica/puller.go internal/store/store.go internal/store/peer.go internal/replica/puller_test.go
git commit -m "feat(replica): poll a primary and apply what changed

A transport error never exits the loop. An unreachable primary is an
expected state on a home network, not a fatal one."
```

---

### Task 11: Configuration keys and wiring

**Files:**
- Modify: `internal/config/config.go`, `internal/config/config_test.go`, `internal/app/serve.go`, `kydns.example.yaml`, `README.md`
- Test: `internal/config/config_test.go`, `internal/app/replication_test.go`

**Interfaces:**
- Consumes: everything above.
- Produces: `config.ReplicationConfig{Listen, Primary string}` on `config.Config` as field `Replication` with yaml key `replication`.

- [ ] **Step 1: Write the failing tests**

Add to `internal/config/config_test.go`:

```go
func TestReplicationOffByDefault(t *testing.T) {
	c := writeConfig(t, "data_dir: /tmp/kydns\n")
	if c.Replication.Listen != "" || c.Replication.Primary != "" {
		t.Fatalf("Replication = %+v, want both empty", c.Replication)
	}
}

// A node that is both primary and replica has no defined behaviour. Refusing
// at startup is the only honest answer.
func TestBothReplicationKeysIsAnError(t *testing.T) {
	_, err := loadConfig(t, "data_dir: /tmp/kydns\nreplication:\n  listen: \":8443\"\n  primary: \"10.0.0.2:8443\"\n")
	if err == nil {
		t.Fatal("a node configured as both primary and replica started")
	}
	for _, want := range []string{"replication.listen", "replication.primary"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %s", err, want)
		}
	}
}

func TestReplicationListenIsValidated(t *testing.T) {
	if _, err := loadConfig(t, "data_dir: /tmp/kydns\nreplication:\n  listen: \"not-an-address\"\n"); err == nil {
		t.Fatal("an unparseable replication.listen was accepted")
	}
}
```

Use the existing helpers in `config_test.go` for writing a temp config; adapt
names to whatever is already there.

- [ ] **Step 2: Run to verify failure**

```bash
CGO_ENABLED=0 go test ./internal/config/ -run Replication -v
```

Expected: FAIL — `c.Replication undefined`.

- [ ] **Step 3: Add the config struct and validation**

In `internal/config/config.go`, add:

```go
// ReplicationConfig is file-owned because it is needed before the database is
// usable, like data_dir and the two listen addresses. Both keys empty means
// standalone.
type ReplicationConfig struct {
	Listen  string `yaml:"listen"`  // primary: the TLS replication listener
	Primary string `yaml:"primary"` // replica: the primary to follow
}
```

Add `Replication ReplicationConfig \`yaml:"replication"\`` to `Config`, and in
`validate()`:

```go
if c.Replication.Listen != "" && c.Replication.Primary != "" {
	return errors.New("replication.listen and replication.primary are mutually " +
		"exclusive: a node is a primary or a replica, never both")
}
if c.Replication.Listen != "" {
	if _, _, err := net.SplitHostPort(c.Replication.Listen); err != nil {
		return fmt.Errorf("replication.listen %q: %w", c.Replication.Listen, err)
	}
}
if c.Replication.Primary != "" {
	if _, _, err := net.SplitHostPort(c.Replication.Primary); err != nil {
		return fmt.Errorf("replication.primary %q: %w", c.Replication.Primary, err)
	}
}
```

- [ ] **Step 4: Wire it into `serve.go`**

In `internal/app/serve.go`, after the store is open and before the DNS server
starts:

- If either replication key is set, `LoadOrCreateIdentity(cfg.DataDir)` and log
  the node ID at startup so an operator can read it without a CLI.
- If `Listen` is set, build the `Source` over the store and start
  `replica.NewServer(...).Serve(l)` in a goroutine.
- If `Primary` is set, build the `Applier` (decode `Config` with the admin
  API's transfer decoder, merge settings with `settings.MergeReplicated`, call
  `store.ApplySnapshot`), and run the puller in a goroutine bound to the
  process context.

Follow the existing goroutine and shutdown patterns in `serve.go` — do not
introduce a new lifecycle style.

- [ ] **Step 5: Write the end-to-end test**

Create `internal/app/replication_test.go`: two stores in one process, paired
directly through the store API (no CLI yet), a service added on the primary,
and an assertion that the replica's registry holds it after one pull. Then
stop the primary and assert the replica still answers.

- [ ] **Step 6: Document the keys**

Add a `replication:` block to `kydns.example.yaml` in the established
commented style, marking both keys **owned by this file** and noting that
setting both is an error. Update the README's "What works today" list.

- [ ] **Step 7: Run everything**

```bash
make test
make build
```

Expected: all PASS, clean build.

- [ ] **Step 8: Commit**

```bash
git add internal/config/ internal/app/ kydns.example.yaml README.md
git commit -m "feat(app,config): start replication from the config file

Both keys set is a startup error. A node is a primary, a replica, or
standalone, decided rather than inferred."
```

---

## What part 2 covers

Deferred to `docs/superpowers/plans/2026-08-13-kydns-replication-operator-surface.md`:

- The `adminapi` middleware that answers `409` to every mutating method on a replica, and its table test over every mutating route.
- `GET /replica/health-status`, and a replica showing health as unknown rather than stale-good when its primary is unreachable.
- `kydns replica invite | join | list | remove | promote`.
- The web UI: disabled edit controls labelled "Managed by *primary*", the replica list on a primary, the staleness banner.
- Promotion and demotion, each behind a confirmation naming what it discards.
- The full end-to-end sequence from the spec: pair, write, verify, kill, promote, re-pair.

## Self-review

**Spec coverage.** Node identity → Task 4. Config keys and the both-set error →
Task 11. Pairing codes, single-use, expiry → Tasks 7, 8. PAKE → Tasks 6, 8.
Fingerprint pinning and mismatch refusal → Task 9. `config_version` discipline
→ Task 1. Settings split → Tasks 1, 2. Snapshot endpoints and version/body
consistency → Tasks 3, 9. Pull loop, backoff, staleness → Task 10. Apply
safety and rollback → Task 5. Schema version refusal → Tasks 3, 10. Blacklist
bodies staying local → Tasks 1, 5. Tokens and admin staying local → Task 5.

Not covered here, and deliberately deferred to part 2: the write gate, health
replication, CLI, UI, promotion and demotion. Every remaining spec section maps
to a part 2 bullet above.

**Type consistency.** `Fingerprint` returns the same string used as
`Peer.NodeID`, `VersionReply.NodeID`, and `Snapshot.NodeID` throughout.
`SnapshotInput` is the store's type; `Snapshot` is the wire type — different
things with deliberately different names, both used consistently.
`MergeReplicated(local, incoming)` keeps that argument order everywhere.

**Known soft spots for the implementer.** Task 5 and Task 9 specify behaviour
and interfaces rather than complete bodies, because both must be written
against store and `net/http` helpers whose exact names need reading first.
Each names the files to read before starting. Task 6 can halt the plan by
design.
