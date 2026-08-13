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

// publish swaps in an already-built snapshot, ordered against Rebuild. It is
// unexported: the only caller that may skip Rebuild's validate-then-swap is
// Service.Set, which has already validated and persisted the same value this
// snapshot was built from. A caller outside this package has no such
// guarantee, and could publish a snapshot that was never persisted (a restart
// would then boot to something else) or one built from a wider baseline than
// the stored row (defeating the exposure guardrail, which trusts the running
// snapshot as "already confirmed").
func (h *Holder) publish(s *Snapshot) {
	h.rebuildMu.Lock()
	defer h.rebuildMu.Unlock()
	h.cur.Store(s)
}

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

// Get returns the settings the server is running.
func (s *Service) Get() (store.Settings, error) {
	if snap := s.h.Current(); snap != nil {
		return snap.Raw, nil
	}
	return store.Settings{}, errors.New("settings are not loaded yet")
}

// CheckWrite reports whether v would be accepted by Set, without writing or
// applying anything: the same rule check and the same constructibility check
// (Build), against the same running baseline. It exists for a caller that
// must know a settings write will succeed before committing to a separate,
// unrelated destructive step (an import replacing the registry, say) — never
// use it in place of Set, since nothing it checks is still true by the time a
// later Set actually runs.
func (s *Service) CheckWrite(v store.Settings, confirmPublic string) error {
	var prev store.Settings
	if cur := s.h.Current(); cur != nil {
		prev = cur.Raw
	}
	if err := ValidateWrite(v, prev, confirmPublic); err != nil {
		return err
	}
	_, err := Build(v)
	return err
}

// Set validates, builds, persists, then publishes the built snapshot. Nothing
// is stored or applied unless every step before it succeeded, and once the
// write succeeds nothing after it can fail: the snapshot is already built, and
// publishing it does no I/O.
func (s *Service) Set(v store.Settings, confirmPublic string) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	// The running values are the baseline for the exposure guardrail, and the
	// holder already has them: no extra read.
	var prev store.Settings
	if cur := s.h.Current(); cur != nil {
		prev = cur.Raw
	}
	if err := ValidateWrite(v, prev, confirmPublic); err != nil {
		return err
	}
	// Store the canonical, masked form of every prefix: the guardrail's whole
	// premise is that the operator can read back what is actually configured,
	// and an entry like "1.2.3.4/0" behaves as 0.0.0.0/0 while reading as a
	// single host. Canonicalizing after validation keeps a bad entry's error
	// message showing exactly what the operator typed.
	v = Canonicalize(v)
	snap, err := Build(v)
	if err != nil {
		return err
	}
	if err := s.w.PutSettings(v); err != nil {
		return err
	}
	s.h.publish(snap)
	s.onApply(snap)
	return nil
}
