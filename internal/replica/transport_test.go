package replica

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"
)

// A peer whose key changed is an impostor or a reinstalled node. Either way it
// is refused, with no prompt and no trust-on-next-use. The pin is checked on
// every handshake, so no request ever completes.
func TestClientRefusesPrimaryWithWrongFingerprint(t *testing.T) {
	client := newIdentity(t)
	_, addr, _ := startServer(t, newFakePeers(client.NodeID), &fakeSource{})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	wrong := newIdentity(t).NodeID
	c, err := NewClient(addr, client, wrong)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	for i := 0; i < 2; i++ {
		if _, err := c.Version(ctx, 0); err == nil {
			t.Fatal("the client read a version from a primary whose fingerprint does not match the pin")
		}
		if _, err := c.Snapshot(ctx); err == nil {
			t.Fatal("the client read a snapshot from a primary whose fingerprint does not match the pin")
		}
	}
}

func TestPinCheckAcceptsTheMatchingFingerprint(t *testing.T) {
	id := newIdentity(t)
	cert, err := selfSignedCert(id)
	if err != nil {
		t.Fatal(err)
	}
	var seen string
	cfg, err := pinnedTLSConfig(newIdentity(t), func(fp string) bool { seen = fp; return true })
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.VerifyPeerCertificate(cert.Certificate, nil); err != nil {
		t.Fatalf("VerifyPeerCertificate on a well-formed peer certificate: %v", err)
	}
	if seen != id.NodeID {
		t.Fatalf("pin check saw fingerprint %q, want the peer's node ID %q", seen, id.NodeID)
	}
}

// The fingerprint is over an Ed25519 key. A certificate carrying any other key
// type has no fingerprint to check, so it is refused rather than waved through.
func TestNonEd25519CertificateIsRefused(t *testing.T) {
	cfg, err := pinnedTLSConfig(newIdentity(t), func(string) bool {
		t.Error("the allow predicate was consulted for a non-Ed25519 certificate")
		return true
	})
	if err != nil {
		t.Fatal(err)
	}
	der, _ := ecdsaCert(t)
	for name, raw := range map[string][][]byte{
		"ecdsa":   {der},
		"garbage": {[]byte("not a certificate")},
		"none":    {},
	} {
		if err := cfg.VerifyPeerCertificate(raw, nil); err == nil {
			t.Errorf("VerifyPeerCertificate accepted a %s certificate", name)
		}
	}
}

// End to end: a client holding an ECDSA certificate gets no data.
func TestServerRefusesNonEd25519Client(t *testing.T) {
	_, addr, fp := startServer(t, newFakePeers(), &fakeSource{})

	cfg, err := pinnedTLSConfig(newIdentity(t), func(got string) bool { return got == fp })
	if err != nil {
		t.Fatal(err)
	}
	der, key := ecdsaCert(t)
	cfg.Certificates = []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
	defer client.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+addr+"/replica/version", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err == nil {
		resp.Body.Close()
		t.Fatalf("server answered %d to a client holding an ECDSA certificate", resp.StatusCode)
	}
}

// hugeSource ships more than a replica will read. Pinned is not trusted with
// unbounded memory.
type hugeSource struct{}

func (hugeSource) Version() (VersionReply, error) {
	return VersionReply{SchemaVersion: SchemaVersion, ConfigVersion: 1}, nil
}

func (hugeSource) HealthStatus() (map[string]string, error) { return nil, nil }

func (hugeSource) Snapshot() (Snapshot, error) {
	big := make([]byte, maxReplyBytes+1024)
	for i := range big {
		big[i] = 'x'
	}
	return Snapshot{
		SchemaVersion: SchemaVersion,
		ConfigVersion: 1,
		Config:        json.RawMessage(`"` + string(big) + `"`),
	}, nil
}

func TestClientRefusesAnOversizedReply(t *testing.T) {
	client := newIdentity(t)
	_, addr, fp := startServer(t, newFakePeers(client.NodeID), hugeSource{})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, err := NewClient(addr, client, fp)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	s, err := c.Snapshot(ctx)
	if err == nil {
		t.Fatalf("Snapshot() read %d bytes of config, want a refusal past %d", len(s.Config), maxReplyBytes)
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("Snapshot() error = %v, want the size ceiling to be the reason", err)
	}
}

func ecdsaCert(t *testing.T) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "not-ed25519"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der, key
}
