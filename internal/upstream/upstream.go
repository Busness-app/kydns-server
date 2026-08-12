package upstream

import (
	"context"
	"fmt"
	"time"

	"github.com/miekg/dns"
)

// Upstream is one configured resolver.
type Upstream interface {
	Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error)

	// Secure reports whether the channel is authenticated and encrypted.
	// Only a secure upstream's AD bit may reach a client.
	Secure() bool

	// String is the spec as configured, for logs and the UI.
	String() string
}

// New builds the resolver a Spec describes.
func New(s Spec, timeout time.Duration) (Upstream, error) {
	switch s.Transport {
	case Plain:
		return &plain{spec: s, timeout: timeout}, nil
	case DoT:
		return newDoT(s, timeout), nil
	}
	return nil, fmt.Errorf("upstream %q: unsupported transport %s", s.Raw, s.Transport)
}

// NewAll parses and builds a whole configured list.
func NewAll(raws []string, timeout time.Duration) ([]Upstream, error) {
	specs, err := ParseAll(raws)
	if err != nil {
		return nil, err
	}
	ups := make([]Upstream, 0, len(specs))
	for _, s := range specs {
		u, err := New(s, timeout)
		if err != nil {
			return nil, err
		}
		ups = append(ups, u)
	}
	return ups, nil
}
