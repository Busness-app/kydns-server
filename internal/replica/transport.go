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
	"math/big"
	"net/http"
	"time"
)

// requestTimeout bounds one replication request. A primary that stops
// answering must not wedge a replica's pull loop.
const requestTimeout = 10 * time.Second

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

// Dial connects to a primary and verifies its fingerprint matches want. A
// mismatch is a failure with no fallback: the operator pinned this key.
func Dial(ctx context.Context, address string, id *Identity, want string) (*Client, error) {
	cfg, err := pinnedTLSConfig(id, func(fp string) bool { return fp == want })
	if err != nil {
		return nil, err
	}
	// Handshake once here so a wrong pin surfaces from Dial rather than from
	// whatever request happens to run first.
	conn, err := (&tls.Dialer{Config: cfg}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", address, err)
	}
	conn.Close()
	return &Client{
		base: "https://" + address,
		http: &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: requestTimeout},
	}, nil
}

func (c *Client) Version(ctx context.Context) (VersionReply, error) {
	var v VersionReply
	err := c.get(ctx, "/replica/version", &v)
	return v, err
}

func (c *Client) Snapshot(ctx context.Context) (Snapshot, error) {
	var s Snapshot
	err := c.get(ctx, "/replica/snapshot", &s)
	return s, err
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
	return json.NewDecoder(resp.Body).Decode(out)
}
