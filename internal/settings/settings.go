package settings

import (
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yoshiofthewire/kydns-server/internal/store"
	"github.com/yoshiofthewire/kydns-server/internal/upstream"
)

// TailscaleCGNAT is the range AllowTailscale adds to the ACL.
const TailscaleCGNAT = "100.64.0.0/10"

// Snapshot is the parsed, immutable form of the settings. Building it is the
// only fallible part of applying a change, so every swap that follows is
// infallible.
type Snapshot struct {
	Raw          store.Settings
	AllowQuery   []netip.Prefix
	ReverseZones []netip.Prefix
	Upstreams    []upstream.Upstream
}

// Build parses v. It is all-or-nothing: any error returns before a caller has
// swapped anything into the running server.
func Build(v store.Settings) (*Snapshot, error) {
	s := &Snapshot{Raw: v}

	allow := append([]string(nil), v.AllowQuery...)
	if v.AllowTailscale {
		allow = append(allow, TailscaleCGNAT)
	}
	for _, c := range allow {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, bad("allow_query", "%q is not a CIDR prefix", c)
		}
		s.AllowQuery = append(s.AllowQuery, p.Masked())
	}
	for _, c := range v.ReverseZones {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, bad("reverse_zones", "%q is not a CIDR prefix", c)
		}
		s.ReverseZones = append(s.ReverseZones, p.Masked())
	}
	ups, err := upstream.NewAll(v.Upstreams, 2*time.Second)
	if err != nil {
		return nil, bad("upstreams", "%s", err)
	}
	s.Upstreams = ups
	return s, nil
}

// Source pulls the stored settings. It returns an error rather than partial
// data, so a transient store failure cannot empty the running configuration.
type Source func() (store.Settings, error)

// Holder owns the live snapshot. Readers on the DNS hot path load a pointer;
// writers call Rebuild, which builds fully before swapping.
type Holder struct {
	src Source
	cur atomic.Pointer[Snapshot]

	// rebuildMu serializes Rebuild so a slower concurrent rebuild cannot
	// publish a stale snapshot after a faster, later one.
	rebuildMu sync.Mutex
}

func NewHolder(src Source) *Holder { return &Holder{src: src} }

// Rebuild pulls fresh settings, builds a complete snapshot, and swaps it in.
// Any error returns before the swap.
func (h *Holder) Rebuild() error {
	h.rebuildMu.Lock()
	defer h.rebuildMu.Unlock()
	v, err := h.src()
	if err != nil {
		return err
	}
	snap, err := Build(v)
	if err != nil {
		return err
	}
	h.cur.Store(snap)
	return nil
}

// Current returns the live snapshot, or nil before the first successful build.
func (h *Holder) Current() *Snapshot { return h.cur.Load() }

// Writer is the store slice this package needs.
type Writer interface {
	PutSettings(store.Settings) error
}

// Service is the single write path for settings: validate, persist, rebuild,
// apply. onApply is injected so this package never imports the runtime.
type Service struct {
	w       Writer
	h       *Holder
	onApply func(*Snapshot)

	// writeMu makes validate-persist-rebuild-apply atomic against a second
	// concurrent Set, so two saves cannot interleave into a state neither asked
	// for.
	writeMu sync.Mutex
}

func NewService(w Writer, h *Holder, onApply func(*Snapshot)) *Service {
	if onApply == nil {
		onApply = func(*Snapshot) {}
	}
	return &Service{w: w, h: h, onApply: onApply}
}

func (s *Service) Holder() *Holder { return s.h }

// Get returns the settings as stored.
func (s *Service) Get() (store.Settings, error) {
	if snap := s.h.Current(); snap != nil {
		return snap.Raw, nil
	}
	return store.Settings{}, errors.New("settings are not loaded yet")
}

// Set validates, persists, rebuilds the snapshot, then applies it. Nothing is
// stored or applied unless every step before it succeeded.
func (s *Service) Set(v store.Settings, confirmPublic string) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	if err := Validate(v, confirmPublic); err != nil {
		return err
	}
	// Build before the write, so an input that validates but cannot be
	// constructed never reaches the database.
	if _, err := Build(v); err != nil {
		return err
	}
	if err := s.w.PutSettings(v); err != nil {
		return err
	}
	if err := s.h.Rebuild(); err != nil {
		return err
	}
	s.onApply(s.h.Current())
	return nil
}
