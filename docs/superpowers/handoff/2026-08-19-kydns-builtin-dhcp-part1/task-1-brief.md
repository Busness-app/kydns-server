### Task 1: Swap the poller's source at runtime

`discovery.Poller` is constructed with its source and `internal/app/serve.go:146` only builds it when `boot.DHCPLeaseFile` is non-empty. That is the entire reason `dhcp_lease_file` requires a restart. Making the source swappable is a prerequisite for enabling DHCP live, and retires that restriction as a side effect.

**Files:**
- Modify: `internal/discovery/poller.go:19-30` (struct), `:100-125` (`Poll`)
- Test: `internal/discovery/poller_test.go`

**Interfaces:**
- Consumes: `dhcp.Source` (`internal/discovery/dhcp/source.go:20`) — `Leases(ctx) ([]Lease, error)`, `Name() string`
- Produces: `func (p *Poller) SetSource(src dhcp.Source)`. `NewPoller` accepts a nil source. `Poll` with a nil source publishes an empty lease set.

- [ ] **Step 1: Write the failing tests**

Append to `internal/discovery/poller_test.go`. `fakeSource` may already exist in this file under another name — reuse it if so rather than adding a second.

```go
type namedSource struct {
	name   string
	leases []dhcp.Lease
}

func (s *namedSource) Leases(context.Context) ([]dhcp.Lease, error) { return s.leases, nil }
func (s *namedSource) Name() string                                 { return s.name }

func TestSetSourceSwapsWithoutRestart(t *testing.T) {
	a := &namedSource{name: "a", leases: []dhcp.Lease{{MAC: "aa", IP: "192.168.1.10", Hostname: "one"}}}
	b := &namedSource{name: "b", leases: []dhcp.Lease{{MAC: "bb", IP: "192.168.1.11", Hostname: "two"}}}

	p := NewPoller(a, time.Hour, func() {}, slog.New(slog.DiscardHandler))
	if err := p.Poll(context.Background()); err != nil {
		t.Fatalf("first poll: %v", err)
	}
	if got := p.Leases(); len(got) != 1 || got[0].Hostname != "one" {
		t.Fatalf("before swap = %+v, want the source-a lease", got)
	}

	p.SetSource(b)
	if err := p.Poll(context.Background()); err != nil {
		t.Fatalf("second poll: %v", err)
	}
	if got := p.Leases(); len(got) != 1 || got[0].Hostname != "two" {
		t.Fatalf("after swap = %+v, want the source-b lease", got)
	}
}

func TestNilSourceRetiresPublishedLeases(t *testing.T) {
	changed := 0
	p := NewPoller(
		&namedSource{name: "a", leases: []dhcp.Lease{{MAC: "aa", IP: "192.168.1.10", Hostname: "one"}}},
		time.Hour, func() { changed++ }, slog.New(slog.DiscardHandler))
	if err := p.Poll(context.Background()); err != nil {
		t.Fatalf("first poll: %v", err)
	}
	if changed != 1 {
		t.Fatalf("onChange called %d times after the first poll, want 1", changed)
	}

	p.SetSource(nil)
	if err := p.Poll(context.Background()); err != nil {
		t.Fatalf("poll with no source: %v", err)
	}
	if got := p.Leases(); len(got) != 0 {
		t.Fatalf("leases after clearing the source = %+v, want none", got)
	}
	if changed != 2 {
		t.Fatalf("onChange called %d times, want 2: retiring every lease is a change", changed)
	}
}

func TestNewPollerToleratesNilSource(t *testing.T) {
	p := NewPoller(nil, time.Hour, func() {}, slog.New(slog.DiscardHandler))
	if err := p.Poll(context.Background()); err != nil {
		t.Fatalf("poll with no source: %v", err)
	}
	if got := p.Leases(); len(got) != 0 {
		t.Fatalf("leases = %+v, want none", got)
	}
}
```


- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/discovery/ -run 'TestSetSource|TestNilSource|TestNewPollerTolerates' -v`
Expected: FAIL to compile with `p.SetSource undefined (type *Poller has no field or method SetSource)`.

- [ ] **Step 3: Move the source behind the config lock**

In `internal/discovery/poller.go`, the `src` field currently sits above `cfgMu` with the immutable fields. Move it under `cfgMu`'s protection by changing the struct comment and adding the accessors. Replace the field declaration block:

```go
type Poller struct {
	onChange func()
	logger   *slog.Logger

	cfgMu    sync.RWMutex
	src      dhcp.Source // nil when discovery is off
	interval time.Duration
	changed  chan struct{} // buffered 1; wakes a Run blocked on the old interval

	mu     sync.RWMutex
	leases []dhcp.Lease
	digest string
}
```

Add below `Interval()`:

```go
// SetSource swaps the lease source. A nil source turns discovery off; the
// next cycle publishes an empty set, which retires the names the old source
// put in the zone. The queued wake makes that cycle immediate rather than one
// interval away.
func (p *Poller) SetSource(src dhcp.Source) {
	p.cfgMu.Lock()
	p.src = src
	p.cfgMu.Unlock()
	select {
	case p.changed <- struct{}{}:
	default:
	}
}

func (p *Poller) source() dhcp.Source {
	p.cfgMu.RLock()
	defer p.cfgMu.RUnlock()
	return p.src
}

// sourceName is only for logs, so it names the absence rather than panicking.
func sourceName(src dhcp.Source) string {
	if src == nil {
		return "none"
	}
	return src.Name()
}
```

- [ ] **Step 4: Make `Poll` and `Run` tolerate a nil source**

Replace the body of `Poll` down to the `digest` call:

```go
func (p *Poller) Poll(ctx context.Context) error {
	src := p.source()
	var leases []dhcp.Lease
	if src != nil {
		var err error
		leases, err = src.Leases(ctx)
		if err != nil {
			return err
		}
	}
	d := digest(leases)
	...
```

In the same function, the two `p.src` references in the change-logging block become `src`, and the log line's source name becomes `sourceName(src)`. In `Run`, the warning log's `p.src.Name()` becomes `sourceName(p.source())`.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./internal/discovery/... -v`
Expected: PASS, including the pre-existing tests.

- [ ] **Step 6: Check for a data race**

Run: `go test ./internal/discovery/ -race -count=2`
Expected: PASS with no race report. `SetSource` writes what `Poll` reads, so this is the check that the lock is actually doing its job.

- [ ] **Step 7: Commit**

```bash
git add internal/discovery/poller.go internal/discovery/poller_test.go
git commit -m "feat(discovery): let the poller's lease source be swapped at runtime

The poller was constructed with its source and only built at all when a
lease file was configured, which is why dhcp_lease_file needed a restart.
A swappable source retires that, and is what will let the built-in DHCP
server be switched on without one."
```

---

