package replica

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"
)

// requestTimeout bounds one replication request. A primary that stops
// answering must not wedge a replica's pull loop.
const requestTimeout = 10 * time.Second

// maxReplyBytes caps what a replica will read from a primary. Pinned is not
// the same as trusted with unbounded memory: a compromised primary must not be
// able to stream a replica out of heap. 16 MiB matches the admin API's own body
// ceiling, so a configuration too large to have been submitted cannot arrive by
// replication either.
const maxReplyBytes = 16 << 20

// selfSignedCert wraps the node's Ed25519 key in a certificate. Nothing but
// the key itself signs it, and the validity is a century because there is no
// renewal path: unpinning, not expiry, is how trust ends here.
func selfSignedCert(id *Identity) (tls.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: id.NodeID},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(100, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, id.PublicKey, id.PrivateKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("self-signed certificate: %w", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: id.PrivateKey}, nil
}

// pinnedTLSConfig authenticates the peer by its key fingerprint.
//
// InsecureSkipVerify disables a CA check that has no CA to run against, and
// VerifyPeerCertificate replaces it with a stricter rule: the peer must
// present one specific key, not merely a certificate someone signed.
func pinnedTLSConfig(id *Identity, allowed func(fp string) bool) (*tls.Config, error) {
	cert, err := selfSignedCert(id)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates:       []tls.Certificate{cert},
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
		// The peer's key is the only credential, so a client that presents none
		// is refused. Verifying it against a CA is impossible; the callback below
		// does the checking instead.
		ClientAuth: tls.RequireAnyClientCert,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			fp, err := leafFingerprint(rawCerts)
			if err != nil {
				return err
			}
			if !allowed(fp) {
				return fmt.Errorf("peer %s is not allowed", fp)
			}
			return nil
		},
	}, nil
}

// leafFingerprint parses the leaf itself, because verifiedChains is empty
// whenever InsecureSkipVerify is set.
func leafFingerprint(rawCerts [][]byte) (string, error) {
	if len(rawCerts) == 0 {
		return "", errors.New("peer presented no certificate")
	}
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return "", fmt.Errorf("parse peer certificate: %w", err)
	}
	pub, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok {
		return "", fmt.Errorf("peer key is %T, want ed25519", leaf.PublicKey)
	}
	return Fingerprint(pub), nil
}

// Client pulls from one primary.
type Client struct {
	base string
	http *http.Client
}

// NewClient builds a client pinned to want. Every handshake it makes enforces
// the pin, so a mismatch is a failed request with no fallback. Connections are
// pooled: a five-second poll reuses one handshake rather than paying for a new
// one each tick.
func NewClient(address string, id *Identity, want string) (*Client, error) {
	cfg, err := pinnedTLSConfig(id, func(fp string) bool { return fp == want })
	if err != nil {
		return nil, err
	}
	return &Client{
		base: "https://" + address,
		http: &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: requestTimeout},
	}, nil
}

// Version reports held so the primary can record how far behind this replica
// is. A primary that answers without being told holds no lag figure at all.
func (c *Client) Version(ctx context.Context, held int64) (VersionReply, error) {
	var v VersionReply
	err := c.get(ctx, fmt.Sprintf("/replica/version?version=%d", held), &v)
	return v, err
}

func (c *Client) Snapshot(ctx context.Context) (Snapshot, error) {
	var s Snapshot
	err := c.get(ctx, "/replica/snapshot", &s)
	return s, err
}

// HealthStatus fetches the primary's current service health. It is its own
// request, not a field on Version, so a health flap never invalidates the
// config version a replica is holding.
func (c *Client) HealthStatus(ctx context.Context) (map[string]string, error) {
	var h HealthReply
	if err := c.get(ctx, "/replica/health-status", &h); err != nil {
		return nil, err
	}
	return h.Statuses, nil
}

func (c *Client) Close() error {
	c.http.CloseIdleConnections()
	return nil
}

func (c *Client) get(ctx context.Context, path string, out any) error {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", path, resp.Status)
	}
	// Read one byte past the ceiling so an oversized reply is an error rather
	// than a silently truncated document.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxReplyBytes+1))
	if err != nil {
		return err
	}
	if len(body) > maxReplyBytes {
		return fmt.Errorf("GET %s: reply exceeds %d bytes", path, maxReplyBytes)
	}
	return json.Unmarshal(body, out)
}
