package replica

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/yoshiofthewire/kydns-server/internal/store"
)

// maxPairBytes caps both directions of the exchange: two short strings.
const maxPairBytes = 4 << 10

// Confirmer decides whether the fingerprint a peer presented really belongs
// to the intended primary. An interactive caller prompts the operator; a
// scripted caller compares against a fingerprint passed on the command line.
// Returning false aborts pairing before anything is sent.
//
// The context it receives carries no deadline of pairing's making: a person
// reading 64 hex characters off two screens is the whole point of this design
// and must not be raced by a network timeout.
type Confirmer func(ctx context.Context, fingerprint string) (bool, error)

// ErrFingerprintRejected is returned when the Confirmer declines. It is a
// distinct error because the CLI reports it differently from a network
// failure: a rejected fingerprint may mean an attacker is in the path.
var ErrFingerprintRejected = errors.New("fingerprint not confirmed")

type pairRequest struct {
	Code string `json:"code"`
}

type pairReply struct {
	NodeID string `json:"node_id"`
}

// PairAsReplica dials address, reads the certificate the peer presents, and
// asks confirm about its fingerprint. Only on approval does it send code. On
// success it records the primary as the one this node follows and returns its
// fingerprint.
//
// Each dial carries its own budget; the operator's decision carries none.
func PairAsReplica(ctx context.Context, address string, id *Identity, code string,
	confirm Confirmer, state StateStore) (string, error) {
	address, err := peerAddress(address)
	if err != nil {
		return "", err
	}
	fingerprint, err := PeekFingerprint(ctx, address, id)
	if err != nil {
		return "", err
	}
	ok, err := confirm(ctx, fingerprint)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("%w: %s presented %s", ErrFingerprintRejected, address, fingerprint)
	}

	// The code travels on a second connection pinned to what the operator just
	// approved, so nothing between here and there can swap the far end after
	// the confirmation.
	cfg, err := pinnedTLSConfig(id, func(fp string) bool { return fp == fingerprint })
	if err != nil {
		return "", err
	}
	body, err := json.Marshal(pairRequest{Code: code})
	if err != nil {
		return "", err
	}
	postCtx, cancelPost := context.WithTimeout(ctx, requestTimeout)
	defer cancelPost()
	// codeql[go/request-forgery] peerAddress accepts only an operator-supplied IP:port.
	req, err := http.NewRequestWithContext(postCtx, http.MethodPost, (&url.URL{
		Scheme: "https",
		Host:   address,
		Path:   "/replica/pair",
	}).String(), bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("pair with %s: %s", address, resp.Status)
	}
	var reply pairReply
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxPairBytes)).Decode(&reply); err != nil {
		return "", err
	}
	// The primary names itself; it may only name the key it proved it holds.
	if reply.NodeID != fingerprint {
		return "", fmt.Errorf("pair with %s: claimed node %q but holds key %s", address, reply.NodeID, fingerprint)
	}
	// replica_state is where "the primary I follow" lives. Version 0 because
	// nothing has been pulled yet, which is also what re-pairing should mean.
	if err := state.SetReplicaState(fingerprint, 0); err != nil {
		return "", fmt.Errorf("record primary %s: %w", fingerprint, err)
	}
	return fingerprint, nil
}

// PeekFingerprint handshakes and hangs up. Nothing is written, so a peer the
// operator goes on to decline never receives a request at all. It is exported
// because the CLI shows this fingerprint to the operator on one call and pairs
// on a second: the connection being confirmed cannot be held open across an
// operator's decision made on another machine.
func PeekFingerprint(ctx context.Context, address string, id *Identity) (string, error) {
	var err error
	address, err = peerAddress(address)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	cfg, err := pinnedTLSConfig(id, func(string) bool { return true })
	if err != nil {
		return "", err
	}
	conn, err := (&tls.Dialer{Config: cfg}).DialContext(ctx, "tcp", address)
	if err != nil {
		return "", fmt.Errorf("dial %s: %w", address, err)
	}
	defer conn.Close()
	certs := conn.(*tls.Conn).ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "", fmt.Errorf("%s presented no certificate", address)
	}
	return leafFingerprint([][]byte{certs[0].Raw})
}

// peerAddress keeps pairing's network target to the documented IP:port form.
// Hostnames and URL syntax are rejected before either dial is made.
func peerAddress(raw string) (string, error) {
	host, port, err := net.SplitHostPort(raw)
	if err != nil || net.ParseIP(host) == nil {
		return "", fmt.Errorf("peer address must be an IP:port: %q", raw)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("peer address has invalid port: %q", raw)
	}
	return net.JoinHostPort(host, strconv.Itoa(n)), nil
}

func (s *Server) handlePair(w http.ResponseWriter, r *http.Request) {
	// The pin comes from the certificate on this connection. A fingerprint read
	// out of the body would let a caller enroll any identity it liked.
	fp, ok := peerFingerprint(r)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	var req pairRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, maxPairBytes)).Decode(&req); err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	// One refusal for unknown, expired and spent alike: which of the three it
	// was is not something a guesser gets to learn.
	if !s.book.Redeem(req.Code) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	// No address: replication is a pull, so the primary never dials this peer.
	if err := s.peers.PairPeer(store.Peer{NodeID: fp, Label: fp[:12], PairedAt: time.Now().Unix()}); err != nil {
		http.Error(w, "pairing failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(pairReply{NodeID: s.id.NodeID})
}
