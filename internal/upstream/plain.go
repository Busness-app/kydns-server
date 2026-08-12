package upstream

import (
	"context"
	"time"

	"github.com/miekg/dns"
)

// plain is UDP with a TCP retry on truncation: DNS as it has always been on the
// wire, and the only transport whose answers cannot be authenticated.
type plain struct {
	spec    Spec
	timeout time.Duration
}

func (p *plain) Secure() bool   { return false }
func (p *plain) String() string { return p.spec.Raw }

func (p *plain) Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	udp := &dns.Client{Net: "udp", Timeout: p.timeout}
	resp, _, err := udp.ExchangeContext(ctx, m, p.spec.Addr)
	if err != nil {
		return nil, err
	}
	if resp.Truncated {
		tcp := &dns.Client{Net: "tcp", Timeout: p.timeout}
		resp, _, err = tcp.ExchangeContext(ctx, m, p.spec.Addr)
		if err != nil {
			return nil, err
		}
	}
	return resp, nil
}
