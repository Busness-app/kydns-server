package settings

import (
	"errors"
	"testing"

	"github.com/yoshiofthewire/kydns-server/internal/store"
)

func TestBuildParsesEverything(t *testing.T) {
	v := valid()
	v.ReverseZones = []string{"192.168.1.0/24"}
	v.Upstreams = []string{"tls://1.1.1.1:853", "udp://192.168.1.1:53"}

	snap, err := Build(v)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(snap.Upstreams) != 2 {
		t.Fatalf("got %d upstreams, want 2", len(snap.Upstreams))
	}
	// Upstreams are tried in order, so Build must not reorder them.
	if snap.Upstreams[0].String() != "tls://1.1.1.1:853" {
		t.Errorf("upstream order changed: %s", snap.Upstreams[0])
	}
	if len(snap.ReverseZones) != 1 || snap.ReverseZones[0].String() != "192.168.1.0/24" {
		t.Errorf("reverse zones: %v", snap.ReverseZones)
	}
	if len(snap.AllowQuery) != 1 {
		t.Fatalf("allow_query: %v", snap.AllowQuery)
	}
}

// AllowTailscale is a checkbox, not a range the operator types. The snapshot is
// what the ACL reads, so the range has to be in it.
func TestBuildAddsTailscaleRange(t *testing.T) {
	v := valid()
	v.AllowTailscale = true
	snap, err := Build(v)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range snap.AllowQuery {
		if p.String() == "100.64.0.0/10" {
			found = true
		}
	}
	if !found {
		t.Errorf("allow_tailscale on, but CGNAT is not in the ACL: %v", snap.AllowQuery)
	}

	v.AllowTailscale = false
	snap, err = Build(v)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range snap.AllowQuery {
		if p.String() == "100.64.0.0/10" {
			t.Error("allow_tailscale off, but CGNAT is in the ACL")
		}
	}
}

// Build is the only fallible step of an apply. It must fail before anything is
// swapped, never halfway through.
func TestBuildFailsWholeOnBadUpstream(t *testing.T) {
	v := valid()
	v.Upstreams = []string{"tls://1.1.1.1:853", "tls://example.com:853"}
	if _, err := Build(v); err == nil {
		t.Fatal("Build accepted a hostname upstream; it must fail before any swap")
	}
}

func TestBuildKeepsRaw(t *testing.T) {
	v := valid()
	v.TTL = 120
	snap, err := Build(v)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Raw.TTL != 120 {
		t.Errorf("Raw.TTL is %d, want 120", snap.Raw.TTL)
	}
}

// fakeWriter is the store slice this package needs. Depending on an interface
// keeps the test a struct literal, matching health.Lister.
type fakeWriter struct {
	cur     store.Settings
	writes  int
	failErr error

	// narrowWrites counts PutDHCPSettings, so a test can tell the two write
	// paths apart rather than inferring one from what landed.
	narrowWrites int

	// renames records the zone move, so a test can prove Set routed the write
	// through the transactional path rather than the plain one.
	renames [][2]string
}

func (f *fakeWriter) PutSettings(v store.Settings) error {
	if f.failErr != nil {
		return f.failErr
	}
	f.cur = v
	f.writes++
	return nil
}

// PutDHCPSettings overlays the eight columns the real UPDATE touches, so a
// test sees exactly what the store would have left behind.
func (f *fakeWriter) PutDHCPSettings(v store.Settings) error {
	if f.failErr != nil {
		return f.failErr
	}
	f.cur.DHCPEnabled, f.cur.DHCPInterface = v.DHCPEnabled, v.DHCPInterface
	f.cur.DHCPRangeStart, f.cur.DHCPRangeEnd = v.DHCPRangeStart, v.DHCPRangeEnd
	f.cur.DHCPGateway, f.cur.DHCPLeaseSeconds = v.DHCPGateway, v.DHCPLeaseSeconds
	f.cur.DHCPSecondaryDNS, f.cur.DHCPAllowForeign = v.DHCPSecondaryDNS, v.DHCPAllowForeign
	f.narrowWrites++
	return nil
}

func (f *fakeWriter) PutSettingsRenamingZone(v store.Settings, from, to string) (int, error) {
	if f.failErr != nil {
		return 0, f.failErr
	}
	f.cur = v
	f.writes++
	f.renames = append(f.renames, [2]string{from, to})
	return 0, nil
}

func newTestService(t *testing.T) (*fakeWriter, *Service, *[]*Snapshot) {
	t.Helper()
	w := &fakeWriter{cur: valid()}
	h := NewHolder(func() (store.Settings, error) { return w.cur, nil })
	if err := h.Rebuild(); err != nil {
		t.Fatalf("initial rebuild: %v", err)
	}
	var applied []*Snapshot
	svc := NewService(w, h, func(s *Snapshot) { applied = append(applied, s) }, nil)
	return w, svc, &applied
}

func TestServiceSetPersistsRebuildsAndApplies(t *testing.T) {
	w, svc, applied := newTestService(t)

	v := valid()
	v.TTL = 120
	if err := svc.Set(v, ""); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if w.cur.TTL != 120 {
		t.Errorf("not persisted: %d", w.cur.TTL)
	}
	if len(*applied) != 1 || (*applied)[0].Raw.TTL != 120 {
		t.Fatalf("apply did not see the new snapshot: %v", *applied)
	}
	if svc.Holder().Current().Raw.TTL != 120 {
		t.Error("the holder still serves the old snapshot")
	}
}

// Two stored public prefixes cannot both be retyped in one confirmation field,
// so re-confirming them on every save would lock the operator out of their own
// settings for good. Set takes the baseline from the running snapshot.
func TestServiceSetDoesNotReConfirmStoredExposure(t *testing.T) {
	w, svc, applied := newTestService(t)
	w.cur.AllowQuery = []string{"0.0.0.0/0", "8.8.8.0/24"}
	if err := svc.Holder().Rebuild(); err != nil {
		t.Fatal(err)
	}

	v := w.cur
	v.TTL = 120
	if err := svc.Set(v, ""); err != nil {
		t.Fatalf("an unrelated save was blocked by an already-stored ACL: %v", err)
	}
	if len(*applied) != 1 || (*applied)[0].Raw.TTL != 120 {
		t.Fatalf("apply did not see the new snapshot: %v", *applied)
	}

	// The guardrail still gates what is actually new.
	v.AllowQuery = append(append([]string(nil), v.AllowQuery...), "9.9.9.0/24")
	if err := svc.Set(v, ""); err == nil {
		t.Fatal("a newly added public range was saved with no confirmation")
	}
}

// A rejected save must leave both the database and the running server alone.
func TestServiceSetRejectsBeforeWriting(t *testing.T) {
	w, svc, applied := newTestService(t)
	before := w.writes

	v := valid()
	v.AllowQuery = []string{"0.0.0.0/0"}
	if err := svc.Set(v, ""); err == nil {
		t.Fatal("an unconfirmed public range was saved")
	}
	if w.writes != before {
		t.Error("a rejected save still wrote to the database")
	}
	if len(*applied) != 0 {
		t.Error("a rejected save still applied to the running server")
	}
}

// A store failure must not apply either: the running server and the database
// have to agree.
func TestServiceSetDoesNotApplyWhenTheWriteFails(t *testing.T) {
	w, svc, applied := newTestService(t)
	w.failErr = errors.New("disk full")

	v := valid()
	v.TTL = 120
	if err := svc.Set(v, ""); err == nil {
		t.Fatal("Set reported success after the write failed")
	}
	if len(*applied) != 0 {
		t.Error("applied a change that was never stored")
	}
}

// Concurrent reads of the snapshot while it is being replaced must never see a
// torn value: the source alternates between two known TTLs, and the reader
// checks the exact value it observes, not just non-nil. Run with -race for
// this to mean anything.
func TestHolderConcurrentRebuild(t *testing.T) {
	const ttlA, ttlB = 60, 120
	next := ttlA
	h := NewHolder(func() (store.Settings, error) {
		v := valid()
		v.TTL = next
		if next == ttlA {
			next = ttlB
		} else {
			next = ttlA
		}
		return v, nil
	})
	if err := h.Rebuild(); err != nil {
		t.Fatal(err)
	}

	stop := make(chan struct{})
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		for {
			select {
			case <-stop:
				return
			default:
			}
			snap := h.Current()
			if snap == nil {
				t.Error("Current returned nil after the first build")
				return
			}
			if snap.Raw.TTL != ttlA && snap.Raw.TTL != ttlB {
				t.Errorf("Current returned a torn TTL: %d", snap.Raw.TTL)
				return
			}
		}
	}()

	for i := 0; i < 500; i++ {
		if err := h.Rebuild(); err != nil {
			t.Error(err)
			break
		}
	}
	close(stop)
	<-readDone
}

// A store failure that only shows up after the write already committed - a
// SQLite read hiccup on the very next query, say - must not be reported as a
// save failure: Set no longer reads back through Source at all once the write
// has succeeded.
func TestServiceSetDoesNotReadSourceAfterAWriteSucceeds(t *testing.T) {
	w := &fakeWriter{cur: valid()}
	reads := 0
	h := NewHolder(func() (store.Settings, error) {
		reads++
		return store.Settings{}, errors.New("read failed")
	})
	// Seed the holder without going through the failing source.
	h.publish(&Snapshot{Raw: valid()})

	var applied []*Snapshot
	svc := NewService(w, h, func(s *Snapshot) { applied = append(applied, s) }, nil)

	v := valid()
	v.TTL = 120
	if err := svc.Set(v, ""); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if reads != 0 {
		t.Errorf("Set read through Source %d times; it must not read Source at all", reads)
	}
	if w.cur.TTL != 120 {
		t.Errorf("not persisted: %d", w.cur.TTL)
	}
	if len(applied) != 1 || applied[0].Raw.TTL != 120 {
		t.Fatalf("apply did not see the new snapshot: %v", applied)
	}
	if h.Current().Raw.TTL != 120 {
		t.Error("the holder still serves the old snapshot")
	}
}

// Changing the private domain has to move the manual records with it, in the
// same transaction as the settings row. Anything else strands every record
// outside the zone the server now serves.
func TestSetRenamesTheZoneWhenTheDomainChanges(t *testing.T) {
	w, svc, _ := newTestService(t)

	v := valid()
	v.PrivateDomain = "lan.example"
	if err := svc.Set(v, ""); err != nil {
		t.Fatalf("Set: %v", err)
	}

	if len(w.renames) != 1 {
		t.Fatalf("renames = %v, want one zone move", w.renames)
	}
	if w.renames[0] != [2]string{"home.arpa.", "lan.example."} {
		t.Errorf("renamed %v, want home.arpa. -> lan.example.", w.renames[0])
	}
	if w.writes != 1 {
		t.Errorf("writes = %d, want the settings written exactly once", w.writes)
	}
}

// Every other setting must keep taking the plain write path: a rename that ran
// on an unrelated save would rewrite records for no reason.
func TestSetDoesNotRenameWhenTheDomainIsUnchanged(t *testing.T) {
	w, svc, _ := newTestService(t)

	v := valid()
	v.TTL = 120
	if err := svc.Set(v, ""); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if len(w.renames) != 0 {
		t.Errorf("renamed %v on a change that left the domain alone", w.renames)
	}
}

// Case and a trailing dot are presentation, not a different zone.
func TestSetTreatsTheSameDomainDifferentlyWrittenAsUnchanged(t *testing.T) {
	w, svc, _ := newTestService(t)

	v := valid()
	v.PrivateDomain = "Home.Arpa."
	if err := svc.Set(v, ""); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if len(w.renames) != 0 {
		t.Errorf("renamed %v for the same zone written differently", w.renames)
	}
}
