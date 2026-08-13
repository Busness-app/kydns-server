package replica

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// fakePrimary counts what the loop asked for, so a test can prove a poll did
// not fetch rather than merely that nothing changed.
type fakePrimary struct {
	version        int64
	schemaVersion  int
	nodeID         string
	versionErr     error
	snapshotErr    error
	versionCalls   int
	snapshotCalls  int
	closes         int
	heldReported   []int64
	healthStatuses map[string]string
	healthErr      error
	healthCalls    int
}

func (f *fakePrimary) Version(_ context.Context, held int64) (VersionReply, error) {
	f.versionCalls++
	f.heldReported = append(f.heldReported, held)
	if f.versionErr != nil {
		return VersionReply{}, f.versionErr
	}
	return VersionReply{SchemaVersion: f.schema(), ConfigVersion: f.version, NodeID: f.id()}, nil
}

func (f *fakePrimary) Snapshot(context.Context) (Snapshot, error) {
	f.snapshotCalls++
	if f.snapshotErr != nil {
		return Snapshot{}, f.snapshotErr
	}
	return Snapshot{
		SchemaVersion: f.schema(),
		ConfigVersion: f.version,
		NodeID:        f.id(),
		Config:        json.RawMessage(`{}`),
	}, nil
}

func (f *fakePrimary) HealthStatus(context.Context) (map[string]string, error) {
	f.healthCalls++
	if f.healthErr != nil {
		return nil, f.healthErr
	}
	return f.healthStatuses, nil
}

func (f *fakePrimary) Close() error { f.closes++; return nil }

func (f *fakePrimary) schema() int {
	if f.schemaVersion == 0 {
		return SchemaVersion
	}
	return f.schemaVersion
}

func (f *fakePrimary) id() string {
	if f.nodeID == "" {
		return pinnedFP
	}
	return f.nodeID
}

type fakeApplier struct {
	calls int
	err   error
	got   []string
}

func (a *fakeApplier) Apply(cfg json.RawMessage) error {
	a.calls++
	a.got = append(a.got, string(cfg))
	return a.err
}

type fakeState struct {
	nodeID  string
	version int64
	writes  int
}

func (s *fakeState) ReplicaState() (string, int64, error) { return s.nodeID, s.version, nil }

func (s *fakeState) SetReplicaState(nodeID string, version int64) error {
	s.writes++
	s.nodeID, s.version = nodeID, version
	return nil
}

// clock is the only time source in this file. Nothing here sleeps.
type clock struct{ t time.Time }

func (c *clock) now() time.Time      { return c.t }
func (c *clock) add(d time.Duration) { c.t = c.t.Add(d) }

// pinnedFP is the fingerprint every test puller dialled, and the only node ID
// a reply is allowed to name. fakePrimary answers with it by default.
const pinnedFP = "primary-fp"

func newTestPuller(p *fakePrimary, ap Applier, st StateStore, now func() time.Time) *Puller {
	return newLoggingPuller(p, ap, st, now, nil)
}

func newLoggingPuller(p *fakePrimary, ap Applier, st StateStore, now func() time.Time, log *slog.Logger) *Puller {
	return NewPuller(PullerConfig{
		Dial:     func(context.Context) (Primary, error) { return p, nil },
		Pinned:   pinnedFP,
		Apply:    ap,
		State:    st,
		Interval: 5 * time.Second,
		Ceiling:  60 * time.Second,
		Now:      now,
		Logger:   log,
	})
}

func TestUnchangedVersionDoesNotFetch(t *testing.T) {
	prim := &fakePrimary{version: 7}
	ap := &fakeApplier{}
	st := &fakeState{nodeID: pinnedFP, version: 7}
	c := &clock{t: time.Unix(1000, 0)}
	p := newTestPuller(prim, ap, st, c.now)

	p.poll(context.Background())

	if prim.snapshotCalls != 0 {
		t.Fatalf("snapshot fetches = %d, want 0 for an unchanged version", prim.snapshotCalls)
	}
	if ap.calls != 0 {
		t.Fatalf("apply calls = %d, want 0", ap.calls)
	}
	if got := p.Status(); got.LastSyncAt != c.t || got.LastError != "" {
		t.Fatalf("Status() = %+v, want a fresh sync and no error", got)
	}
}

func TestChangedVersionAppliesOnce(t *testing.T) {
	prim := &fakePrimary{version: 8}
	ap := &fakeApplier{}
	st := &fakeState{nodeID: pinnedFP, version: 7}
	c := &clock{t: time.Unix(1000, 0)}
	p := newTestPuller(prim, ap, st, c.now)

	p.poll(context.Background())
	c.add(5 * time.Second)
	p.poll(context.Background())

	if ap.calls != 1 {
		t.Fatalf("apply calls = %d over two ticks at one version, want 1", ap.calls)
	}
	if prim.snapshotCalls != 1 {
		t.Fatalf("snapshot fetches = %d, want 1", prim.snapshotCalls)
	}
	if st.version != 8 || st.nodeID != "primary-fp" {
		t.Fatalf("persisted state = %q/%d, want primary-fp/8", st.nodeID, st.version)
	}
	if got := p.Status(); got.LastVersion != 8 || got.PrimaryNodeID != "primary-fp" {
		t.Fatalf("Status() = %+v, want version 8 from primary-fp", got)
	}
}

func TestFailedApplyKeepsTheOldVersionAndRetries(t *testing.T) {
	prim := &fakePrimary{version: 9}
	ap := &fakeApplier{err: errors.New("bad document")}
	st := &fakeState{nodeID: pinnedFP, version: 4}
	c := &clock{t: time.Unix(1000, 0)}
	p := newTestPuller(prim, ap, st, c.now)

	p.poll(context.Background())
	if got := p.Status(); got.LastVersion != 4 {
		t.Fatalf("LastVersion = %d after a failed apply, want the old 4", got.LastVersion)
	}
	if st.writes != 0 {
		t.Fatalf("persisted %d times after a failed apply, want 0", st.writes)
	}
	if got := p.Status().LastError; !strings.Contains(got, "bad document") {
		t.Fatalf("LastError = %q, want the apply failure", got)
	}

	// The retry is the point: the next tick fetches version 9 again.
	c.add(5 * time.Second)
	p.poll(context.Background())
	if prim.snapshotCalls != 2 || ap.calls != 2 {
		t.Fatalf("second tick fetched %d and applied %d times, want 2 and 2", prim.snapshotCalls, ap.calls)
	}

	// And once the document is good the version finally moves.
	ap.err = nil
	c.add(5 * time.Second)
	p.poll(context.Background())
	if got := p.Status(); got.LastVersion != 9 || got.LastError != "" {
		t.Fatalf("Status() = %+v after a good apply, want version 9 and no error", got)
	}
}

func TestSchemaVersionMismatchIsRefusedAndNamesBothVersions(t *testing.T) {
	prim := &fakePrimary{version: 3, schemaVersion: SchemaVersion + 1}
	ap := &fakeApplier{}
	p := newTestPuller(prim, ap, &fakeState{}, (&clock{t: time.Unix(1000, 0)}).now)

	p.poll(context.Background())

	if prim.snapshotCalls != 0 || ap.calls != 0 {
		t.Fatalf("fetched %d and applied %d, want 0 and 0 for a mismatched schema", prim.snapshotCalls, ap.calls)
	}
	msg := p.Status().LastError
	// An operator has to be able to see which side to upgrade.
	for _, want := range []string{"2", "1"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("LastError = %q, want it to name schema version %s", msg, want)
		}
	}
}

func TestUnreachablePrimaryBacksOffAndGoesStale(t *testing.T) {
	prim := &fakePrimary{versionErr: errors.New("connection refused")}
	c := &clock{t: time.Unix(1000, 0)}
	p := newTestPuller(prim, &fakeApplier{}, &fakeState{}, c.now)

	p.poll(context.Background())
	first := p.wait()
	if first <= 5*time.Second {
		t.Fatalf("wait after one failure = %v, want more than the 5s interval", first)
	}

	prev := first
	for i := 0; i < 10; i++ {
		c.add(prev)
		p.poll(context.Background())
		got := p.wait()
		if got > 60*time.Second {
			t.Fatalf("wait = %v after %d failures, want the 60s ceiling at most", got, i+2)
		}
		if got < prev {
			t.Fatalf("wait shrank from %v to %v while still failing", prev, got)
		}
		prev = got
	}
	if prev != 60*time.Second {
		t.Fatalf("wait settled at %v, want the 60s ceiling", prev)
	}

	got := p.Status()
	if !got.Stale {
		t.Fatal("Status().Stale = false after a long unreachable stretch, want true")
	}
	if !strings.Contains(got.LastError, "connection refused") {
		t.Fatalf("LastError = %q, want the transport failure", got.LastError)
	}

	// The primary comes back: the backoff collapses to the plain interval.
	prim.versionErr = nil
	p.poll(context.Background())
	if p.wait() != 5*time.Second {
		t.Fatalf("wait = %v after the primary answered, want the 5s interval", p.wait())
	}
	if p.Status().Stale {
		t.Fatal("Status().Stale = true right after a good poll, want false")
	}
}

func TestStatusReportsStaleAfterSixtySeconds(t *testing.T) {
	prim := &fakePrimary{version: 2}
	c := &clock{t: time.Unix(1000, 0)}
	p := newTestPuller(prim, &fakeApplier{}, &fakeState{nodeID: pinnedFP, version: 2}, c.now)

	p.poll(context.Background())
	if p.Status().Stale {
		t.Fatal("Stale = true immediately after a sync, want false")
	}
	c.add(60 * time.Second)
	if p.Status().Stale {
		t.Fatal("Stale = true at exactly 60s, want false")
	}
	c.add(time.Second)
	if !p.Status().Stale {
		t.Fatal("Stale = false at 61s since the last sync, want true")
	}
}

func TestPersistedVersionSurvivesRestart(t *testing.T) {
	prim := &fakePrimary{version: 12}
	ap := &fakeApplier{}
	st := &fakeState{}
	c := &clock{t: time.Unix(1000, 0)}

	newTestPuller(prim, ap, st, c.now).poll(context.Background())
	if ap.calls != 1 {
		t.Fatalf("apply calls = %d on the first run, want 1", ap.calls)
	}

	// A fresh Puller over the same state is a restarted process.
	restarted := newTestPuller(prim, ap, st, c.now)
	restarted.poll(context.Background())

	if ap.calls != 1 {
		t.Fatalf("apply calls = %d after a restart at the same version, want 1", ap.calls)
	}
	if prim.snapshotCalls != 1 {
		t.Fatalf("snapshot fetches = %d after a restart, want 1", prim.snapshotCalls)
	}
	if got := restarted.Status().LastVersion; got != 12 {
		t.Fatalf("LastVersion = %d on a restarted puller, want the persisted 12", got)
	}
}

// A primary held for a single poll must not be able to leave its own key
// pinned behind it. The reply names a node; the handshake proves one, and only
// the proven one is ever written down.
func TestReplyNamingAnotherKeyIsRefusedAndNotPersisted(t *testing.T) {
	prim := &fakePrimary{version: 5, nodeID: "attacker-fp"}
	ap := &fakeApplier{}
	st := &fakeState{nodeID: pinnedFP, version: 4}
	p := newTestPuller(prim, ap, st, (&clock{t: time.Unix(1000, 0)}).now)

	p.poll(context.Background())

	if ap.calls != 0 || prim.snapshotCalls != 0 {
		t.Fatalf("applied %d and fetched %d from a primary naming another key, want 0 and 0",
			ap.calls, prim.snapshotCalls)
	}
	if st.writes != 0 || st.nodeID != pinnedFP {
		t.Fatalf("persisted state = %q after %d writes, want the pin %q untouched",
			st.nodeID, st.writes, pinnedFP)
	}
	if got := p.Status(); got.PrimaryNodeID != pinnedFP || !strings.Contains(got.LastError, "attacker-fp") {
		t.Fatalf("Status() = %+v, want the pin kept and the claim named", got)
	}
}

// The same refusal on the snapshot, which is the reply that used to be written
// straight into replica_state.
func TestSnapshotNamingAnotherKeyIsNotPersisted(t *testing.T) {
	// The version reply is honest and the snapshot is not, so checking only the
	// version would let this through.
	prim := &liarSnapshot{fakePrimary: &fakePrimary{version: 5}}
	ap := &fakeApplier{}
	st := &fakeState{nodeID: pinnedFP, version: 4}
	p := NewPuller(PullerConfig{
		Dial:     func(context.Context) (Primary, error) { return prim, nil },
		Pinned:   pinnedFP,
		Apply:    ap,
		State:    st,
		Interval: 5 * time.Second,
		Ceiling:  60 * time.Second,
		Now:      (&clock{t: time.Unix(1000, 0)}).now,
	})

	p.poll(context.Background())

	if ap.calls != 0 {
		t.Fatalf("applied %d snapshots claiming another key, want 0", ap.calls)
	}
	if st.writes != 0 || st.nodeID != pinnedFP {
		t.Fatalf("persisted %q after %d writes, want the pin %q untouched", st.nodeID, st.writes, pinnedFP)
	}
}

// liarSnapshot answers the version honestly and the snapshot as someone else.
type liarSnapshot struct{ *fakePrimary }

func (l *liarSnapshot) Snapshot(ctx context.Context) (Snapshot, error) {
	s, err := l.fakePrimary.Snapshot(ctx)
	s.NodeID = "attacker-fp"
	return s, err
}

// A primary that is down overnight is one log line, not one every five
// seconds. Recovery is one more.
func TestFailureLogsOncePerTransition(t *testing.T) {
	prim := &fakePrimary{version: 3, versionErr: errors.New("connection refused")}
	var buf bytes.Buffer
	c := &clock{t: time.Unix(1000, 0)}
	p := newLoggingPuller(prim, &fakeApplier{}, &fakeState{}, c.now,
		slog.New(slog.NewTextHandler(&buf, nil)))

	for i := 0; i < 5; i++ {
		p.poll(context.Background())
	}
	if got := strings.Count(buf.String(), "connection refused"); got != 1 {
		t.Fatalf("five failing polls logged %d lines, want 1:\n%s", got, buf.String())
	}

	prim.versionErr = nil
	p.poll(context.Background())
	if !strings.Contains(buf.String(), "replication recovered") {
		t.Fatalf("the primary came back and nothing said so:\n%s", buf.String())
	}
	if got := strings.Count(buf.String(), "replication recovered"); got != 1 {
		t.Fatalf("recovery logged %d times, want 1", got)
	}
	p.poll(context.Background())
	if got := strings.Count(buf.String(), "replication recovered"); got != 1 {
		t.Fatalf("a second healthy poll logged recovery again (%d)", got)
	}
}

// A fingerprint mismatch is not an ordinary network hiccup: it is logged at
// error, because it may mean someone is answering for the primary.
func TestFingerprintMismatchLogsAtError(t *testing.T) {
	prim := &fakePrimary{version: 3, nodeID: "attacker-fp"}
	var buf bytes.Buffer
	p := newLoggingPuller(prim, &fakeApplier{}, &fakeState{}, (&clock{t: time.Unix(1000, 0)}).now,
		slog.New(slog.NewTextHandler(&buf, nil)))

	p.poll(context.Background())

	if !strings.Contains(buf.String(), "level=ERROR") || !strings.Contains(buf.String(), "attacker-fp") {
		t.Fatalf("a fingerprint mismatch logged:\n%s\nwant an error naming the key that answered", buf.String())
	}
}

// Polling every five seconds must not cost a TLS handshake every five seconds.
func TestConnectionIsReusedAcrossTicks(t *testing.T) {
	prim := &fakePrimary{version: 2}
	dials := 0
	p := NewPuller(PullerConfig{
		Dial:     func(context.Context) (Primary, error) { dials++; return prim, nil },
		Pinned:   pinnedFP,
		Apply:    &fakeApplier{},
		State:    &fakeState{nodeID: pinnedFP, version: 2},
		Interval: 5 * time.Second,
		Ceiling:  60 * time.Second,
		Now:      (&clock{t: time.Unix(1000, 0)}).now,
	})

	for i := 0; i < 3; i++ {
		p.poll(context.Background())
	}
	if dials != 1 || prim.closes != 0 {
		t.Fatalf("three ticks cost %d dials and %d closes, want 1 and 0", dials, prim.closes)
	}

	// A broken connection is thrown away, not reused.
	prim.versionErr = errors.New("connection reset")
	p.poll(context.Background())
	if prim.closes != 1 {
		t.Fatalf("a failed poll closed %d connections, want 1", prim.closes)
	}
	prim.versionErr = nil
	p.poll(context.Background())
	if dials != 2 {
		t.Fatalf("dials = %d after a failure, want a fresh connection (2)", dials)
	}
}

// The primary cannot know how far behind a replica is unless the replica says
// so. Version lag is measured from what the replica reports, not from what the
// primary just read out of its own store.
func TestPollReportsTheVersionItHolds(t *testing.T) {
	prim := &fakePrimary{version: 9}
	st := &fakeState{nodeID: pinnedFP, version: 4}
	p := newTestPuller(prim, &fakeApplier{}, st, (&clock{t: time.Unix(1000, 0)}).now)

	p.poll(context.Background())
	p.poll(context.Background())

	want := []int64{4, 9}
	if len(prim.heldReported) != 2 || prim.heldReported[0] != want[0] || prim.heldReported[1] != want[1] {
		t.Fatalf("reported held versions %v, want %v", prim.heldReported, want)
	}
}

func TestRunReturnsWhenTheContextIsCancelled(t *testing.T) {
	prim := &fakePrimary{version: 1}
	p := newTestPuller(prim, &fakeApplier{}, &fakeState{}, time.Now)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.Run(ctx); close(done) }()
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return on cancellation; it waited for the next tick")
	}
}
