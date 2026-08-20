### Task 2: Settings columns and the lease table

Two schema changes land together because they are one migration. Note what is deliberately absent: neither the new settings columns nor the lease table appears in any `cv_` trigger, which is what makes them node-local.

**Files:**
- Modify: `internal/store/model.go:79-98` (`Settings`), `internal/store/store.go:120-138` (base schema) and `:256` (`migrations`), `internal/store/settings.go`
- Test: `internal/store/settings_test.go`, `internal/store/store_test.go`

**Interfaces:**
- Produces: `store.Settings` gains `DHCPEnabled bool`, `DHCPInterface string`, `DHCPRangeStart string`, `DHCPRangeEnd string`, `DHCPGateway string`, `DHCPLeaseSeconds int`, `DHCPSecondaryDNS string`. New type `store.DHCPLease{MAC, IP, Hostname string; ExpiresAt, LastSeen int64}`.

- [ ] **Step 1: Write the failing tests**

Add to `internal/store/settings_test.go`:

```go
func TestSettingsRoundTripsDHCPFields(t *testing.T) {
	s := openTestStore(t)
	v, _, err := s.Settings()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	v.DHCPEnabled = true
	v.DHCPInterface = "eth0"
	v.DHCPRangeStart = "192.168.1.128"
	v.DHCPRangeEnd = "192.168.1.254"
	v.DHCPGateway = "192.168.1.1"
	v.DHCPLeaseSeconds = 86400
	v.DHCPSecondaryDNS = "192.168.1.3"
	if err := s.PutSettings(v); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, ok, err := s.Settings()
	if err != nil || !ok {
		t.Fatalf("read back: %v ok=%v", err, ok)
	}
	if got != v {
		t.Fatalf("round trip = %+v, want %+v", got, v)
	}
}

func TestDHCPSettingsDoNotBumpConfigVersion(t *testing.T) {
	s := openTestStore(t)
	v, _, err := s.Settings()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := s.PutSettings(v); err != nil {
		t.Fatalf("seed write: %v", err)
	}
	before, err := s.ConfigVersion()
	if err != nil {
		t.Fatalf("version: %v", err)
	}

	v.DHCPEnabled = true
	v.DHCPInterface = "eth0"
	if err := s.PutSettings(v); err != nil {
		t.Fatalf("write: %v", err)
	}

	after, err := s.ConfigVersion()
	if err != nil {
		t.Fatalf("version: %v", err)
	}
	if after != before {
		t.Fatalf("config version moved from %d to %d; DHCP settings are node-local and must not replicate", before, after)
	}
}
```

`openTestStore` is the existing helper in this package. If it is named differently, use whatever the neighbouring tests use — do not add a second one.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/store/ -run 'TestSettingsRoundTripsDHCP|TestDHCPSettingsDoNot' -v`
Expected: FAIL to compile with `v.DHCPEnabled undefined`.

- [ ] **Step 3: Add the fields to the model**

In `internal/store/model.go`, extend `Settings` after `HealthWorkers`:

```go
	// DHCP settings drive the built-in server. They are node-local: no cv_
	// trigger names them, so a replica never hears about them, and two DHCP
	// servers on one segment is exactly what that prevents.
	DHCPEnabled      bool
	DHCPInterface    string
	DHCPRangeStart   string
	DHCPRangeEnd     string
	DHCPGateway      string
	DHCPLeaseSeconds int
	DHCPSecondaryDNS string
```

And add the lease type at the end of the file:

```go
// DHCPLease is one address the built-in server has handed out. It is stored
// so a restart cannot re-issue an address that is still in use. Times are
// Unix seconds.
type DHCPLease struct {
	MAC       string
	IP        string
	Hostname  string
	ExpiresAt int64
	LastSeen  int64
}
```

- [ ] **Step 4: Add the columns to the base schema**

In `internal/store/store.go`, inside the `CREATE TABLE IF NOT EXISTS settings` block at line 120, add after `health_workers`:

```sql
  dhcp_enabled       INTEGER NOT NULL DEFAULT 0,
  dhcp_interface     TEXT NOT NULL DEFAULT '',
  dhcp_range_start   TEXT NOT NULL DEFAULT '',
  dhcp_range_end     TEXT NOT NULL DEFAULT '',
  dhcp_gateway       TEXT NOT NULL DEFAULT '',
  dhcp_lease_seconds INTEGER NOT NULL DEFAULT 86400,
  dhcp_secondary_dns TEXT NOT NULL DEFAULT ''
```

Remember the comma after `health_workers INTEGER NOT NULL`.

In the same schema string, after the `records` table and before the `cv_` triggers, add:

```sql
CREATE TABLE IF NOT EXISTS dhcp_leases (
  mac        TEXT PRIMARY KEY,
  ip         TEXT NOT NULL UNIQUE,
  hostname   TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  last_seen  INTEGER NOT NULL
);
```

Do not add a `cv_dhcp_leases_*` trigger. Leases never replicate.

- [ ] **Step 5: Add the migration**

Append a fourth entry to the `migrations` slice in `internal/store/store.go:256`:

```go
	`ALTER TABLE settings ADD COLUMN dhcp_enabled INTEGER NOT NULL DEFAULT 0;
	 ALTER TABLE settings ADD COLUMN dhcp_interface TEXT NOT NULL DEFAULT '';
	 ALTER TABLE settings ADD COLUMN dhcp_range_start TEXT NOT NULL DEFAULT '';
	 ALTER TABLE settings ADD COLUMN dhcp_range_end TEXT NOT NULL DEFAULT '';
	 ALTER TABLE settings ADD COLUMN dhcp_gateway TEXT NOT NULL DEFAULT '';
	 ALTER TABLE settings ADD COLUMN dhcp_lease_seconds INTEGER NOT NULL DEFAULT 86400;
	 ALTER TABLE settings ADD COLUMN dhcp_secondary_dns TEXT NOT NULL DEFAULT '';
	 CREATE TABLE IF NOT EXISTS dhcp_leases (
	   mac        TEXT PRIMARY KEY,
	   ip         TEXT NOT NULL UNIQUE,
	   hostname   TEXT NOT NULL,
	   expires_at INTEGER NOT NULL,
	   last_seen  INTEGER NOT NULL
	 );`,
```

- [ ] **Step 6: Read and write the new columns**

In `internal/store/settings.go`, extend the `SELECT` in `Settings()` with `dhcp_enabled, dhcp_interface, dhcp_range_start, dhcp_range_end, dhcp_gateway, dhcp_lease_seconds, dhcp_secondary_dns` and the matching `Scan` targets:

```go
		&v.HealthInterval, &v.HealthTimeout, &v.HealthWorkers,
		&v.DHCPEnabled, &v.DHCPInterface, &v.DHCPRangeStart, &v.DHCPRangeEnd,
		&v.DHCPGateway, &v.DHCPLeaseSeconds, &v.DHCPSecondaryDNS)
```

In `putSettings`, add the seven columns to the `INSERT` list, seven more `?` placeholders, seven `excluded.` assignments in the `DO UPDATE SET` clause, and the seven values in order at the end of the argument list.

- [ ] **Step 7: Run the tests to verify they pass**

Run: `go test ./internal/store/... -v`
Expected: PASS. `TestDHCPSettingsDoNotBumpConfigVersion` passing is the proof that the trigger's `WHEN` clause was left alone.

- [ ] **Step 8: Verify the migration runs on an existing database**

The store tests open fresh databases, which take the base schema and skip migrations. Confirm the upgrade path separately:

Run: `go test ./internal/store/ -run 'Migrat|Upgrade' -v`
Expected: PASS. If this package has no existing migration test, add one that opens a store, closes it, sets `PRAGMA user_version = 3`, reopens, and asserts `Settings()` succeeds — the failure this guards against is an `ALTER` running against a column that already exists.

- [ ] **Step 9: Commit**

```bash
git add internal/store/
git commit -m "feat(store): add DHCP settings columns and the lease table

Both are node-local by construction: no cv_ trigger names them, so a
replica never hears about either. A test asserts the config version does
not move when a DHCP setting changes."
```

---

