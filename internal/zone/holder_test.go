package zone

import (
	"errors"
	"net/netip"
	"sync"
	"testing"

	"github.com/Busness-app/kydns-server/internal/store"
)

func TestRebuildSwapsSnapshot(t *testing.T) {
	addr := "192.168.1.20"
	h := NewHolder(func() (Input, error) {
		return Input{
			Zone:         "home.arpa.",
			ReverseZones: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
			Services: []store.Service{{
				ID: 1, Name: "kypost", Addresses: []store.Address{{Address: addr}},
			}},
		}, nil
	}, nil)
	if h.Current() != nil {
		t.Fatal("Current() before first Rebuild should be nil")
	}
	if err := h.Rebuild(); err != nil {
		t.Fatal(err)
	}
	if got := h.Current().Lookup("", "kypost.home.arpa."); len(got) != 1 || got[0].Value != "192.168.1.20" {
		t.Fatalf("after first rebuild = %+v", got)
	}
	addr = "192.168.1.21"
	if err := h.Rebuild(); err != nil {
		t.Fatal(err)
	}
	if got := h.Current().Lookup("", "kypost.home.arpa."); got[0].Value != "192.168.1.21" {
		t.Errorf("after second rebuild = %q, want the new address", got[0].Value)
	}
}

func TestGenerationIncrementsPerRebuild(t *testing.T) {
	h := NewHolder(func() (Input, error) { return Input{Zone: "home.arpa."}, nil }, nil)
	for want := uint32(1); want <= 3; want++ {
		if err := h.Rebuild(); err != nil {
			t.Fatal(err)
		}
		if got := h.Current().Generation; got != want {
			t.Errorf("Generation = %d, want %d", got, want)
		}
	}
}

// A failed build must never take DNS dark: the previous snapshot keeps serving.
func TestFailedRebuildKeepsPreviousSnapshot(t *testing.T) {
	fail := false
	h := NewHolder(func() (Input, error) {
		if fail {
			return Input{}, errors.New("source unavailable")
		}
		return Input{
			Zone:     "home.arpa.",
			Services: []store.Service{{ID: 1, Name: "nas", Addresses: []store.Address{{Address: "192.168.1.30"}}}},
		}, nil
	}, nil)
	if err := h.Rebuild(); err != nil {
		t.Fatal(err)
	}
	before := h.Current()

	fail = true
	if err := h.Rebuild(); err == nil {
		t.Fatal("Rebuild() error = nil, want the source error")
	}
	if h.Current() != before {
		t.Error("snapshot was replaced by a failed rebuild")
	}
	if got := h.Current().Lookup("", "nas.home.arpa."); len(got) != 1 {
		t.Error("previous snapshot stopped answering after a failed rebuild")
	}
}

// An invalid registry state (CNAME conflict) must fail the build, not panic
// or install a half-built snapshot.
func TestInvalidInputFailsBuild(t *testing.T) {
	h := NewHolder(func() (Input, error) {
		return Input{
			Zone: "home.arpa.",
			Records: []store.Record{
				{Name: "mail.home.arpa.", Type: "A", Value: "192.168.1.20"},
				{Name: "mail.home.arpa.", Type: "CNAME", Value: "nas.home.arpa."},
			},
		}, nil
	}, nil)
	if err := h.Rebuild(); err == nil {
		t.Fatal("Rebuild() error = nil, want CNAME conflict")
	}
	if h.Current() != nil {
		t.Error("a failed first build installed a snapshot")
	}
}

// The SOA serial must never go backwards, even across a failed attempt.
func TestGenerationAdvancesAcrossFailure(t *testing.T) {
	fail := false
	h := NewHolder(func() (Input, error) {
		if fail {
			return Input{}, errors.New("nope")
		}
		return Input{Zone: "home.arpa."}, nil
	}, nil)
	if err := h.Rebuild(); err != nil {
		t.Fatal(err)
	}
	first := h.Current().Generation

	fail = true
	_ = h.Rebuild()
	fail = false
	if err := h.Rebuild(); err != nil {
		t.Fatal(err)
	}
	if got := h.Current().Generation; got <= first {
		t.Errorf("Generation = %d after a failed attempt, want greater than %d", got, first)
	}
}

func TestConcurrentReadsDuringRebuild(t *testing.T) {
	h := NewHolder(func() (Input, error) {
		return Input{
			Zone:     "home.arpa.",
			Services: []store.Service{{ID: 1, Name: "nas", Addresses: []store.Address{{Address: "192.168.1.30"}}}},
		}, nil
	}, nil)
	if err := h.Rebuild(); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				if s := h.Current(); s == nil || len(s.Lookup("", "nas.home.arpa.")) != 1 {
					t.Error("reader saw an inconsistent snapshot")
					return
				}
			}
		}()
	}
	for j := 0; j < 50; j++ {
		if err := h.Rebuild(); err != nil {
			t.Error(err)
			break
		}
	}
	wg.Wait()
}
