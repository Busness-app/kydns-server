### Task 3: Lease persistence

**Files:**
- Create: `internal/store/dhcplease.go`
- Test: `internal/store/dhcplease_test.go`

**Interfaces:**
- Consumes: `store.DHCPLease` from Task 2.
- Produces: `func (s *Store) DHCPLeases() ([]DHCPLease, error)`, `func (s *Store) PutDHCPLease(l DHCPLease) error`, `func (s *Store) DeleteDHCPLease(mac string) error`, `func (s *Store) DeleteExpiredDHCPLeases(now int64) (int, error)`.

- [ ] **Step 1: Write the failing tests**

Create `internal/store/dhcplease_test.go`:

```go
package store

import "testing"

func TestDHCPLeaseRoundTrip(t *testing.T) {
	s := openTestStore(t)
	l := DHCPLease{MAC: "aa:bb:cc:dd:ee:ff", IP: "192.168.1.130", Hostname: "laptop", ExpiresAt: 2000, LastSeen: 1000}
	if err := s.PutDHCPLease(l); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := s.DHCPLeases()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 || got[0] != l {
		t.Fatalf("leases = %+v, want exactly %+v", got, l)
	}
}

func TestPutDHCPLeaseMovesAnAddressToANewMAC(t *testing.T) {
	s := openTestStore(t)
	old := DHCPLease{MAC: "aa:aa:aa:aa:aa:aa", IP: "192.168.1.130", Hostname: "old", ExpiresAt: 2000, LastSeen: 1000}
	if err := s.PutDHCPLease(old); err != nil {
		t.Fatalf("put old: %v", err)
	}
	// The IP column is UNIQUE. Re-issuing a released address to a different
	// client is normal, so this must succeed and evict the old row rather
	// than fail on the constraint.
	next := DHCPLease{MAC: "bb:bb:bb:bb:bb:bb", IP: "192.168.1.130", Hostname: "new", ExpiresAt: 3000, LastSeen: 2500}
	if err := s.PutDHCPLease(next); err != nil {
		t.Fatalf("put next: %v", err)
	}
	got, err := s.DHCPLeases()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 || got[0] != next {
		t.Fatalf("leases = %+v, want only %+v", got, next)
	}
}

func TestPutDHCPLeaseMovesAClientToANewAddress(t *testing.T) {
	s := openTestStore(t)
	mac := "aa:bb:cc:dd:ee:ff"
	if err := s.PutDHCPLease(DHCPLease{MAC: mac, IP: "192.168.1.130", Hostname: "laptop", ExpiresAt: 2000, LastSeen: 1000}); err != nil {
		t.Fatalf("put first: %v", err)
	}
	next := DHCPLease{MAC: mac, IP: "192.168.1.131", Hostname: "laptop", ExpiresAt: 3000, LastSeen: 2500}
	if err := s.PutDHCPLease(next); err != nil {
		t.Fatalf("put second: %v", err)
	}
	got, err := s.DHCPLeases()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 || got[0] != next {
		t.Fatalf("leases = %+v, want only %+v", got, next)
	}
}

func TestDeleteExpiredDHCPLeases(t *testing.T) {
	s := openTestStore(t)
	for _, l := range []DHCPLease{
		{MAC: "aa:aa:aa:aa:aa:aa", IP: "192.168.1.130", Hostname: "gone", ExpiresAt: 1000, LastSeen: 500},
		{MAC: "bb:bb:bb:bb:bb:bb", IP: "192.168.1.131", Hostname: "kept", ExpiresAt: 9000, LastSeen: 500},
	} {
		if err := s.PutDHCPLease(l); err != nil {
			t.Fatalf("put %s: %v", l.MAC, err)
		}
	}
	n, err := s.DeleteExpiredDHCPLeases(5000)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if n != 1 {
		t.Fatalf("pruned %d, want 1", n)
	}
	got, err := s.DHCPLeases()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 || got[0].Hostname != "kept" {
		t.Fatalf("leases = %+v, want only the unexpired one", got)
	}
}

func TestDeleteDHCPLease(t *testing.T) {
	s := openTestStore(t)
	mac := "aa:bb:cc:dd:ee:ff"
	if err := s.PutDHCPLease(DHCPLease{MAC: mac, IP: "192.168.1.130", Hostname: "laptop", ExpiresAt: 2000, LastSeen: 1000}); err != nil {
		t.Fatalf("put: %v", err)
	}
	if err := s.DeleteDHCPLease(mac); err != nil {
		t.Fatalf("delete: %v", err)
	}
	got, err := s.DHCPLeases()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("leases = %+v, want none", got)
	}
	// Releasing a lease that is already gone is normal: a client can send
	// RELEASE twice. It must not error.
	if err := s.DeleteDHCPLease(mac); err != nil {
		t.Fatalf("second delete: %v", err)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/store/ -run 'DHCPLease' -v`
Expected: FAIL to compile with `s.PutDHCPLease undefined`.

- [ ] **Step 3: Write the implementation**

Create `internal/store/dhcplease.go`:

```go
package store

// DHCP leases are node-local: they are not replicated and no cv_ trigger
// names this table. They are persisted only so a restart cannot re-issue an
// address that is still in use.

// DHCPLeases returns every stored lease, expired ones included. Pruning is
// the allocator's job, on the schedule that suits it.
func (s *Store) DHCPLeases() ([]DHCPLease, error) {
	rows, err := s.db.Query(
		`SELECT mac, ip, hostname, expires_at, last_seen FROM dhcp_leases ORDER BY ip`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DHCPLease
	for rows.Next() {
		var l DHCPLease
		if err := rows.Scan(&l.MAC, &l.IP, &l.Hostname, &l.ExpiresAt, &l.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// PutDHCPLease stores one lease. Both keys move: a client can be given a new
// address, and a released address can be re-issued to a different client. The
// two deletes clear whichever unique key the new row would collide with, so
// this is an upsert on either.
func (s *Store) PutDHCPLease(l DHCPLease) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM dhcp_leases WHERE ip = ? AND mac <> ?`, l.IP, l.MAC); err != nil {
		return err
	}
	if _, err := tx.Exec(`
INSERT INTO dhcp_leases (mac, ip, hostname, expires_at, last_seen)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(mac) DO UPDATE SET
  ip=excluded.ip, hostname=excluded.hostname,
  expires_at=excluded.expires_at, last_seen=excluded.last_seen`,
		l.MAC, l.IP, l.Hostname, l.ExpiresAt, l.LastSeen); err != nil {
		return err
	}
	return tx.Commit()
}

// DeleteDHCPLease drops one lease. Deleting one that is not there is not an
// error: a client may send RELEASE more than once.
func (s *Store) DeleteDHCPLease(mac string) error {
	_, err := s.db.Exec(`DELETE FROM dhcp_leases WHERE mac = ?`, mac)
	return err
}

// DeleteExpiredDHCPLeases prunes leases that expired at or before now, and
// returns how many went.
func (s *Store) DeleteExpiredDHCPLeases(now int64) (int, error) {
	res, err := s.db.Exec(`DELETE FROM dhcp_leases WHERE expires_at <= ?`, now)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/store/ -run 'DHCPLease' -v`
Expected: PASS, all five.

- [ ] **Step 5: Commit**

```bash
git add internal/store/dhcplease.go internal/store/dhcplease_test.go
git commit -m "feat(store): persist DHCP leases

Both unique keys move in practice - a client gets a new address, an
address is re-issued to a new client - so the write clears whichever key
would collide before inserting."
```

---

