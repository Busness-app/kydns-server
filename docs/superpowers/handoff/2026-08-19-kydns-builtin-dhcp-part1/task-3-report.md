# Task 3: Lease Persistence - Report

## Summary

Implemented DHCP lease persistence with four methods:
- `DHCPLeases() ([]DHCPLease, error)` - list all leases
- `PutDHCPLease(l DHCPLease) error` - store or update a lease
- `DeleteDHCPLease(mac string) error` - delete a specific lease
- `DeleteExpiredDHCPLeases(now int64) (int, error)` - prune expired leases

## Changes Made

### Files Created
1. **internal/store/dhcplease_test.go** - 120 lines
   - Five comprehensive test cases covering all CRUD operations
   - Tests validate lease round-trip storage, address/MAC mobility, expiration, and idempotent deletion

2. **internal/store/dhcplease.go** - 69 lines
   - Full implementation of all four methods
   - Uses transactional upsert to handle the dual unique keys (MAC primary, IP unique)

## Implementation Details

### Key Design: Transactional Upsert for Dual Unique Keys

The `PutDHCPLease` method uses an explicit transaction because `dhcp_leases` has two unique constraints that both move:
1. MAC is the primary key
2. IP is UNIQUE

The strategy (delete-then-upsert):
1. Delete any existing row with the same IP but different MAC (handles address re-issue to new client)
2. Upsert on MAC key (handles client moving to new address via ON CONFLICT)

This atomic transaction ensures either scenario works correctly:
- Client gets a new address: old MAC row is updated to new IP
- Released address is re-issued: old client row is deleted, new client gets the address

### Lease Locality

Per the brief, DHCP leases are node-local:
- No cv_ replication triggers
- No cluster replication code
- Leases are persisted only to prevent address re-issue after restart

## Verification

### Test Results
All five test cases passed:
```
=== RUN   TestDHCPLeaseRoundTrip
--- PASS: TestDHCPLeaseRoundTrip (0.00s)
=== RUN   TestPutDHCPLeaseMovesAnAddressToANewMAC
--- PASS: TestPutDHCPLeaseMovesAnAddressToANewMAC (0.00s)
=== RUN   TestPutDHCPLeaseMovesAClientToANewAddress
--- PASS: TestPutDHCPLeaseMovesAClientToANewAddress (0.00s)
=== RUN   TestDeleteExpiredDHCPLeases
--- PASS: TestDeleteExpiredDHCPLeases (0.00s)
=== RUN   TestDeleteDHCPLease
--- PASS: TestDeleteDHCPLease (0.00s)
PASS
ok  	github.com/yoshiofthewire/kydns-server/internal/store	0.020s
```

### Full Suite
```
go test ./internal/store/... -count=1
ok  	github.com/yoshiofthewire/kydns-server/internal/store	0.182s
```

### Linting
```
go vet ./internal/store/
(no output = no issues)
```

## Process Notes

### Correction Applied
The brief called `openTestStore(t)` but the actual test helper is `open(t)` at internal/store/store_test.go:10. All test cases were updated to use the correct helper.

### Work Completed
- ✓ Step 1: Written tests using corrected helper function
- ✓ Step 2: Verified tests fail with expected "undefined method" error
- ✓ Step 3: Implemented all four methods exactly as specified in brief
- ✓ Step 4: Verified all tests pass
- ✓ Step 5: Committed with proper message

## Commit Details

```
commit ce6fd7c64c9e5a6fdb789c8dbb32ca8a2b04f68b
Author: Yoshiofthewire <yoshi@urlxl.com>
Date:   Tue Aug 19 2026

    feat(store): persist DHCP leases

    Both unique keys move in practice - a client gets a new address, an
    address is re-issued to a new client - so the write clears whichever key
    would collide before inserting.
```

## Notes for Next Tasks

- The `PutDHCPLease` transactional approach is deliberate and tested; three tests specifically validate the dual-key mobility
- The delete-then-upsert pattern is safe under concurrent writes because the transaction is atomic at the SQLite level
- `DHCPLeases()` returns expired leases; pruning is delegated to the DHCP allocator on its own schedule
- `DeleteDHCPLease()` is idempotent; second release of same MAC does not error (correct DHCP behavior)
- No changes needed to replication code or cluster mechanics
