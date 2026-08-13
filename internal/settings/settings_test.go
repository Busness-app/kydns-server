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
}

func (f *fakeWriter) PutSettings(v store.Settings) error {
	if f.failErr != nil {
		return f.failErr
	}
	f.cur = v
	f.writes++
	return nil
}

func newTestService(t *testing.T) (*fakeWriter, *Service, *[]*Snapshot) {
	t.Helper()
	w := &fakeWriter{cur: valid()}
	h := NewHolder(func() (store.Settings, error) { return w.cur, nil })
	if err := h.Rebuild(); err != nil {
		t.Fatalf("initial rebuild: %v", err)
	}
	var applied []*Snapshot
	svc := NewService(w, h, func(s *Snapshot) { applied = append(applied, s) })
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

// Concurrent reads of the snapshot while it is being replaced must not tear.
// Run with -race for this to mean anything.
func TestHolderConcurrentRebuild(t *testing.T) {
	w := &fakeWriter{cur: valid()}
	h := NewHolder(func() (store.Settings, error) { return w.cur, nil })
	if err := h.Rebuild(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 500; i++ {
			if h.Current() == nil {
				t.Error("Current returned nil after the first build")
				return
			}
		}
	}()
	for i := 0; i < 500; i++ {
		if err := h.Rebuild(); err != nil {
			t.Fatal(err)
		}
	}
	<-done
}
