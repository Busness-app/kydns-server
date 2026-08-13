package upstream

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const dohMediaType = "application/dns-message"

// doh speaks RFC 8484. net/http pools connections, so unlike DoT there is
// nothing to keep alive by hand.
type doh struct {
	spec   Spec
	client *http.Client
}

func newDoH(s Spec, timeout time.Duration) *doh {
	dialer := &net.Dialer{Timeout: timeout}
	return &doh{
		spec: s,
		client: &http.Client{
			Timeout: timeout,
			// RFC 8484 clients have no need to follow redirects, and a
			// redirect to plaintext http:// would resend the query unencrypted.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig(s),
				// The URL carries the server name; the socket always goes to
				// the configured IP, so no hostname needs resolving.
				DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
					return dialer.DialContext(ctx, network, s.Addr)
				},
				ForceAttemptHTTP2: true,
				IdleConnTimeout:   30 * time.Second,
			},
		},
	}
}

func (d *doh) Secure() bool   { return true }
func (d *doh) String() string { return d.spec.Raw }

// Close releases pooled connections held by the client's transport.
func (d *doh) Close() error {
	d.client.CloseIdleConnections()
	return nil
}

func (d *doh) Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	q := m.Copy()
	q.Id = 0 // RFC 8484 section 4.1
	wire, err := q.Pack()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.spec.URL, bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", dohMediaType)
	req.Header.Set("Accept", dohMediaType)

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("upstream %s: HTTP %s", d.spec.Raw, resp.Status)
	}
	ct, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || !strings.EqualFold(ct, dohMediaType) {
		return nil, fmt.Errorf("upstream %s: content type %q, want %s", d.spec.Raw, resp.Header.Get("Content-Type"), dohMediaType)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, dns.MaxMsgSize+1))
	if err != nil {
		return nil, err
	}
	if len(body) > dns.MaxMsgSize {
		return nil, fmt.Errorf("upstream %s: response exceeds %d bytes", d.spec.Raw, dns.MaxMsgSize)
	}
	out := new(dns.Msg)
	if err := out.Unpack(body); err != nil {
		return nil, fmt.Errorf("upstream %s: %w", d.spec.Raw, err)
	}
	out.Id = m.Id
	return out, nil
}
