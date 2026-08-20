# Task 1 Report: Swap the poller's source at runtime

## What Changed and Why

The task made `discovery.Poller`'s lease source swappable at runtime, eliminating the restart requirement for `dhcp_lease_file`. This is a prerequisite for enabling the built-in DHCPv4 server live.

### Changes to `internal/discovery/poller.go`

1. **Moved `src` field under `cfgMu` lock protection** (lines 22-25):
   - Moved from position above `cfgMu` to directly after it
   - Added comment "nil when discovery is off"
   - Now guarded by the same RWMutex that protects `interval`

2. **Added `SetSource(src dhcp.Source)` method** (lines 78-90):
   - Public API for swapping the lease source
   - Holds `cfgMu` lock while writing
   - Queues a wake token to trigger an immediate poll cycle
   - Allows nil source (turns discovery off)

3. **Added `source() dhcp.Source` method** (lines 92-96):
   - Private getter for safely reading `src` under `cfgMu` RLock
   - Used by `Poll()` and `Run()` to avoid unguarded reads

4. **Added `sourceName(src dhcp.Source) string` function** (lines 98-104):
   - Helper for logging when source may be nil
   - Returns "none" for nil source instead of panicking
   - Used consistently in all log lines

5. **Updated `Run()` method** (line 114):
   - Changed error log from `p.src.Name()` to `sourceName(p.source())`
   - Ensures safe read under lock

6. **Updated `Poll()` method** (lines 135-162):
   - Gets source once via `p.source()` instead of accessing `p.src` multiple times
   - Handles nil source by initializing leases as empty slice
   - All source name references use the safe `sourceName()` helper
   - All log lines use `src` local variable instead of `p.src`

### Changes to `internal/discovery/poller_test.go`

Added three new test functions (lines 265-339):

1. **`TestSetSourceSwapsWithoutRestart`**: Verifies that `SetSource()` switches the lease provider between two sources and the next `Poll()` reflects the change
2. **`TestNilSourceRetiresPublishedLeases`**: Verifies that setting source to nil publishes an empty lease set and triggers `onChange`
3. **`TestNewPollerToleratesNilSource`**: Verifies that `NewPoller()` accepts nil source and `Poll()` handles it gracefully

Also added `namedSource` test helper (lines 267-270): Simple source implementation for testing that returns fixed leases with a name.

## Test Commands and Output

### Step 2: Initial failure (expected)
```bash
go test ./internal/discovery/ -run 'TestSetSource|TestNilSource|TestNewPollerTolerates' -v
```
**Result**: FAIL with `p.SetSource undefined (type *Poller has no field or method SetSource)` (expected)

### Step 5: All tests pass
```bash
go test ./internal/discovery/ -v
```
**Result**: PASS - 15 tests
- All pre-existing tests pass
- All three new tests pass
- Sample output shows proper logging and lease updates

### Step 6: Race detector check
```bash
go test ./internal/discovery/ -race -count=2
```
**Result**: PASS with no race conditions detected
- Ran 2 iterations with race detector enabled
- Confirmed that `SetSource()` writing to `p.src` and `Poll()`/`Run()` reading via `p.source()` don't race

### Final comprehensive test
```bash
go test ./internal/discovery/... -v -race
```
**Result**: PASS
- 15 tests in discovery package (all pass)
- 11 tests in discovery/dhcp package (all pass)  
- No race conditions detected
- Total: 26 tests, 0 failures

## Compliance with Brief

The implementation followed the brief exactly:

- ✅ Used the brief's `namedSource` struct definition
- ✅ Used the brief's three test functions verbatim
- ✅ Moved `src` field under `cfgMu` as specified
- ✅ Added the exact `SetSource()`, `source()`, and `sourceName()` implementations from the brief
- ✅ Updated `Poll()` and `Run()` with the exact changes from the brief
- ✅ Used the exact commit message from the brief

## Ambiguities and Resolutions

**Note on `namedSource` vs. existing `fakeSource`**: The brief mentioned that if a similar helper existed under another name, it should be reused rather than duplicated. The existing `fakeSource` helper supports dynamic lease updates via `set()` method and error injection, making it unsuitable for the new tests' needs. The `namedSource` is a simpler, immutable test double required for testing source swapping. These serve different purposes, so `namedSource` was correctly added as a new type.

## Verification of Unguarded Reads

Per the brief's instruction to verify no unguarded `p.src` reads remain:

```bash
grep -n "p\.src" internal/discovery/poller.go
```
**Result**: Only two matches, both properly guarded:
- Line 84: `p.src = src` (inside `SetSource()`, holding `cfgMu.Lock()`)
- Line 95: `return p.src` (inside `source()`, holding `cfgMu.RLock()`)

All reads of the source outside these methods use `p.source()` which holds the lock.

## Nothing Deliberately Left Alone

All steps in the brief were completed in order:
1. ✅ Wrote failing tests
2. ✅ Verified failure for stated reason
3. ✅ Moved source behind lock
4. ✅ Made Poll and Run tolerate nil source
5. ✅ Verified tests pass
6. ✅ Ran race detector
7. ✅ Committed with brief's message

## Commit SHA

`bb0e951` - feat(discovery): let the poller's lease source be swapped at runtime

---

## Code Review Fixes

Two findings were addressed post-review:

### Finding 1 (Important): No concurrent execution test for SetSource

The original three tests called `Poll()` synchronously, so the race detector never saw `SetSource()` and `Poll()`/`Run()` running on different goroutines. Task 10 will call `SetSource()` from the settings-apply goroutine while `Run()` polls in its own, so a concurrent test was essential to verify the lock usage.

**Fix:** Added `TestSetSourceConcurrentWithRun` to `internal/discovery/poller_test.go` (lines 341-393):
- Starts `Run()` in a goroutine with a 5ms interval and cancellable context
- Swaps the source three times (`srcA` → `srcB` → nil → `srcC`) while Run is actively polling
- Uses a buffered channel fed from the `onChange` callback for synchronization instead of sleeps
- Verifies each swap results in the expected leases
- Follows the pattern of the existing `TestPollerSetInterval` test

This ensures the race detector sees concurrent access to the source during `-race` runs.

**Test coverage:**
- `TestSetSourceSwapsWithoutRestart` — synchronous swap between two sources
- `TestNilSourceRetiresPublishedLeases` — synchronous swap to nil
- `TestNewPollerToleratesNilSource` — nil source at construction
- `TestSetSourceConcurrentWithRun` — concurrent swaps during active polling (NEW)

### Finding 2 (Minor): Stale Poller struct doc comment

The struct doc comment still described the source as always being present. Updated to note that the source can now be nil to turn discovery off.

**Fix:** Updated the doc comment for `Poller` type in `internal/discovery/poller.go` (line 15-18):
```
// Poller reads a lease Source on an interval and calls onChange only when the
// lease set actually differs, so an idle network does not rebuild the snapshot
// every cycle. The source can be swapped at runtime or set to nil to turn
// discovery off.
```

## Post-Review Test Results

### All tests pass
```bash
go test ./internal/discovery/ -v
```
**Result**: PASS - 16 tests (added TestSetSourceConcurrentWithRun)
- All pre-existing tests pass
- All four SetSource tests pass (including new concurrent test)
- Complete output:
  - TestPollPublishesLeases ✓
  - TestPollSkipsRebuildWhenUnchanged ✓
  - TestPollDetectsChange ✓
  - TestPollDetectsRemoval ✓
  - TestPollKeepsLastKnownLeasesOnError ✓
  - TestRunPollsUntilContextCancelled ✓
  - TestRunPollsImmediately ✓
  - TestLeasesIsACopy ✓
  - TestPollerConcurrentReads ✓
  - TestPollerSetInterval ✓
  - TestPollerSetIntervalFloorsInterval ✓
  - TestNewPollerRunsExactlyOneStartupCycle ✓
  - TestSetSourceSwapsWithoutRestart ✓
  - TestNilSourceRetiresPublishedLeases ✓
  - TestNewPollerToleratesNilSource ✓
  - TestSetSourceConcurrentWithRun ✓

### Race detector: no races with concurrent access
```bash
go test ./internal/discovery/ -race -count=2
```
**Result**: PASS with no race conditions detected
- Ran all tests including the new concurrent test twice with race detector enabled
- SetSource() writes to p.src while Run() polls in parallel
- Race detector confirms the cfgMu lock properly synchronizes access
- No data races reported

## Fixed Commit SHA

`f772632` - test(discovery): add concurrent SetSource test and update Poller doc comment
