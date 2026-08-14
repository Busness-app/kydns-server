package replica

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/yoshiofthewire/kydns-server/internal/store"
)

func TestPeerAddressRequiresIPAndPort(t *testing.T) {
	tests := map[string]bool{
		"192.0.2.10:8443":         true,
		"[2001:db8::10]:8443":     true,
		"primary.example:8443":    false,
		"https://192.0.2.10:8443": false,
		"192.0.2.10:0":            false,
	}
	for raw, wantOK := range tests {
		_, err := peerAddress(raw)
		if (err == nil) != wantOK {
			t.Errorf("peerAddress(%q) error = %v, want success %v", raw, err, wantOK)
		}
	}
}

func pairCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// startPairingServer runs the real server so the book and the pin store under
// test are the ones a primary actually uses.
func startPairingServer(t *testing.T, peers PeerStore, book *InviteBook) (addr, primaryFP string) {
	t.Helper()
	id := newIdentity(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(id, peers, &fakeSource{}, book)
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return l.Addr().String(), id.NodeID
}

func newPeerStore(t *testing.T) *store.Store {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "kydns.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// recorder is a primary that remembers every code it was ever handed. An
// assertion that pairing failed would pass even if the code had been sent and
// then refused; this records what actually crossed the wire.
type recorder struct {
	mu       sync.Mutex
	codes    []string
	requests int
}

func (r *recorder) seen() ([]string, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.codes...), r.requests
}

func startRecordingPrimary(t *testing.T) (addr, fp string, rec *recorder) {
	t.Helper()
	id := newIdentity(t)
	rec = &recorder{}
	mux := http.NewServeMux()
	mux.HandleFunc("/replica/pair", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Code string `json:"code"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		rec.mu.Lock()
		rec.requests++
		rec.codes = append(rec.codes, body.Code)
		rec.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"node_id": id.NodeID})
	})
	cfg, err := pinnedTLSConfig(id, func(string) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: mux}
	go srv.Serve(tls.NewListener(l, cfg))
	t.Cleanup(func() { srv.Close() })
	return l.Addr().String(), id.NodeID, rec
}

func acceptAny(context.Context, string) (bool, error) { return true, nil }

// Pairing succeeds, and each side ends up holding the other's fingerprint.
func TestPairingPinsBothWays(t *testing.T) {
	db := newPeerStore(t)
	book := NewInviteBook(time.Minute, time.Now)
	addr, primaryFP := startPairingServer(t, db, book)
	invite, err := book.Mint()
	if err != nil {
		t.Fatal(err)
	}
	replica := newIdentity(t)

	got, err := PairAsReplica(pairCtx(t), addr, replica, invite.Code, acceptAny, &fakeState{})
	if err != nil {
		t.Fatalf("PairAsReplica: %v", err)
	}
	if got != primaryFP {
		t.Fatalf("PairAsReplica returned %q, want the primary's fingerprint %q", got, primaryFP)
	}
	if _, err := db.Peer(replica.NodeID); err != nil {
		t.Fatalf("primary did not pin the replica it just paired with: %v", err)
	}
}

// Pairing records the primary in replica_state, which is the one place that
// means "the primary I follow". peers is the other direction and does not
// answer this question on a node that used to be a primary.
func TestPairingRecordsThePrimaryItFollows(t *testing.T) {
	db := newPeerStore(t)
	book := NewInviteBook(time.Minute, time.Now)
	addr, primaryFP := startPairingServer(t, db, book)
	invite, err := book.Mint()
	if err != nil {
		t.Fatal(err)
	}
	state := newPeerStore(t) // the replica's own database

	if _, err := PairAsReplica(pairCtx(t), addr, newIdentity(t), invite.Code, acceptAny, state); err != nil {
		t.Fatal(err)
	}
	gotID, gotVersion, err := state.ReplicaState()
	if err != nil {
		t.Fatal(err)
	}
	if gotID != primaryFP {
		t.Fatalf("replica_state names %q as the primary, want %q", gotID, primaryFP)
	}
	if gotVersion != 0 {
		t.Fatalf("replica_state version = %d after pairing, want 0: nothing has been pulled yet", gotVersion)
	}
}

// The operator comparing 64 hex characters across two screens is the entire
// reason this design was chosen. Timing that out from a network layer would
// punish exactly the operator who read carefully.
func TestSlowConfirmationIsNotOnAClock(t *testing.T) {
	db := newPeerStore(t)
	book := NewInviteBook(time.Minute, time.Now)
	addr, _ := startPairingServer(t, db, book)
	invite, err := book.Mint()
	if err != nil {
		t.Fatal(err)
	}

	// Waiting out a real deadline would mean sleeping, so the assertion is that
	// there is no deadline to wait out.
	var deadline bool
	confirm := func(ctx context.Context, _ string) (bool, error) {
		_, deadline = ctx.Deadline()
		return true, nil
	}
	if _, err := PairAsReplica(context.Background(), addr, newIdentity(t), invite.Code, confirm, &fakeState{}); err != nil {
		t.Fatalf("PairAsReplica: %v", err)
	}
	if deadline {
		t.Fatal("the confirmer was given a deadline; an operator reading carefully would be cut off mid-comparison")
	}
}

// The whole reason the SSH model closes the PAKE's hole: a declined
// fingerprint must send no code at all.
func TestDeclinedFingerprintSendsNoCode(t *testing.T) {
	addr, _, rec := startRecordingPrimary(t)

	got, err := PairAsReplica(pairCtx(t), addr, newIdentity(t), "SECRETCODE",
		func(context.Context, string) (bool, error) { return false, nil }, &fakeState{})
	if !errors.Is(err, ErrFingerprintRejected) {
		t.Fatalf("PairAsReplica error = %v, want ErrFingerprintRejected", err)
	}
	if got != "" {
		t.Fatalf("PairAsReplica returned fingerprint %q alongside a refusal", got)
	}
	codes, requests := rec.seen()
	if len(codes) != 0 || requests != 0 {
		t.Fatalf("primary received %d requests carrying codes %q; a declined fingerprint must send nothing", requests, codes)
	}
}

// The confirmer is handed the fingerprint of whoever actually answered, so an
// attacker substituting its own certificate is visible to the operator.
func TestConfirmerSeesThePeersRealFingerprint(t *testing.T) {
	honest, honestFP := startPairingServer(t, newFakePeers(), NewInviteBook(time.Minute, time.Now))
	attacker, attackerFP, rec := startRecordingPrimary(t)

	for name, c := range map[string]struct{ addr, want string }{
		"honest":   {honest, honestFP},
		"attacker": {attacker, attackerFP},
	} {
		var seen []string
		_, _ = PairAsReplica(pairCtx(t), c.addr, newIdentity(t), "CODE",
			func(_ context.Context, fp string) (bool, error) {
				seen = append(seen, fp)
				return false, nil
			}, &fakeState{})
		if len(seen) != 1 || seen[0] != c.want {
			t.Fatalf("%s: confirmer saw %q, want the fingerprint of the host that answered %q", name, seen, c.want)
		}
	}
	if codes, _ := rec.seen(); len(codes) != 0 {
		t.Fatalf("attacker received codes %q", codes)
	}
}

// A scripted join with a mismatched expected fingerprint fails closed.
func TestExplicitFingerprintMismatchFailsClosed(t *testing.T) {
	addr, _, rec := startRecordingPrimary(t)
	expected := newIdentity(t).NodeID // the operator pasted a different node's fingerprint

	prompts := 0
	_, err := PairAsReplica(pairCtx(t), addr, newIdentity(t), "SECRETCODE",
		func(_ context.Context, fp string) (bool, error) {
			prompts++
			return fp == expected, nil
		}, &fakeState{})
	if !errors.Is(err, ErrFingerprintRejected) {
		t.Fatalf("PairAsReplica error = %v, want ErrFingerprintRejected", err)
	}
	if prompts != 1 {
		t.Fatalf("confirmer called %d times, want exactly 1", prompts)
	}
	if codes, requests := rec.seen(); len(codes) != 0 || requests != 0 {
		t.Fatalf("primary received %d requests carrying codes %q after a mismatch", requests, codes)
	}
}

// The peek is what the CLI shows an operator before they decide. It hands the
// peer nothing at all, so a peer they go on to decline never heard from them.
func TestPeekFingerprintSendsNoCode(t *testing.T) {
	addr, want, rec := startRecordingPrimary(t)

	got, err := PeekFingerprint(pairCtx(t), addr, newIdentity(t))
	if err != nil {
		t.Fatalf("PeekFingerprint: %v", err)
	}
	if got != want {
		t.Fatalf("PeekFingerprint = %q, want the key that answered %q", got, want)
	}
	if codes, requests := rec.seen(); len(codes) != 0 || requests != 0 {
		t.Fatalf("the peek made %d requests carrying codes %q", requests, codes)
	}
}

// Both dials are on a clock. A peer that accepts a connection and then says
// nothing must not hold the operator's terminal open indefinitely, and the
// budget is requestTimeout rather than whatever the caller happened to pass.
func TestEachPairingDialCarriesTheRequestTimeout(t *testing.T) {
	restore := requestTimeout
	requestTimeout = 50 * time.Millisecond
	t.Cleanup(func() { requestTimeout = restore })

	// Far larger than requestTimeout: a dial that ignored requestTimeout would
	// run until this fired instead, and the elapsed time gives it away.
	const parentBudget = 5 * time.Second
	// Generous enough that a loaded machine does not fail here, small enough
	// that only requestTimeout can have ended the dial.
	const promptly = time.Second

	t.Run("peek", func(t *testing.T) {
		// Accepts TCP and never speaks TLS, so the handshake never completes.
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		go func() {
			var held []net.Conn
			for {
				c, err := l.Accept()
				if err != nil {
					for _, c := range held {
						c.Close()
					}
					return
				}
				held = append(held, c)
			}
		}()

		ctx, cancel := context.WithTimeout(context.Background(), parentBudget)
		defer cancel()
		start := time.Now()
		_, err = PeekFingerprint(ctx, l.Addr().String(), newIdentity(t))
		if err == nil {
			t.Fatal("PeekFingerprint returned a fingerprint from a peer that never handshook")
		}
		if elapsed := time.Since(start); elapsed > promptly {
			t.Fatalf("the peek dial took %v; it is not bounded by requestTimeout", elapsed)
		}
	})

	t.Run("send", func(t *testing.T) {
		// Handshakes, then never answers the request carrying the code.
		id := newIdentity(t)
		block := make(chan struct{})
		t.Cleanup(func() { close(block) })
		cfg, err := pinnedTLSConfig(id, func(string) bool { return true })
		if err != nil {
			t.Fatal(err)
		}
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		srv := &http.Server{Handler: http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			select {
			case <-block:
			case <-r.Context().Done():
			}
		})}
		go srv.Serve(tls.NewListener(l, cfg))
		t.Cleanup(func() { srv.Close() })

		ctx, cancel := context.WithTimeout(context.Background(), parentBudget)
		defer cancel()
		start := time.Now()
		_, err = PairAsReplica(ctx, l.Addr().String(), newIdentity(t), "SECRETCODE", acceptAny, &fakeState{})
		if err == nil {
			t.Fatal("PairAsReplica succeeded against a peer that never replied")
		}
		if elapsed := time.Since(start); elapsed > promptly {
			t.Fatalf("the pairing request took %v; it is not bounded by requestTimeout", elapsed)
		}
	})
}

// unknownCodeError is the refusal an attacker guessing codes gets from this
// server. Expired and spent codes must be indistinguishable from it.
func unknownCodeError(t *testing.T, addr string) string {
	t.Helper()
	_, err := PairAsReplica(pairCtx(t), addr, newIdentity(t), "NOTACODE", acceptAny, &fakeState{})
	if err == nil {
		t.Fatal("PairAsReplica accepted a code that was never minted")
	}
	return err.Error()
}

func TestPairingRejectsWrongCode(t *testing.T) {
	db := newPeerStore(t)
	book := NewInviteBook(time.Minute, time.Now)
	addr, _ := startPairingServer(t, db, book)
	if _, err := book.Mint(); err != nil {
		t.Fatal(err)
	}
	replica := newIdentity(t)

	if _, err := PairAsReplica(pairCtx(t), addr, replica, "WRONGCODE", acceptAny, &fakeState{}); err == nil {
		t.Fatal("PairAsReplica succeeded with a code the book never issued")
	}
	if _, err := db.Peer(replica.NodeID); err == nil {
		t.Fatal("primary pinned a peer that presented a wrong code")
	}
}

func TestPairingRejectsSpentCode(t *testing.T) {
	db := newPeerStore(t)
	book := NewInviteBook(time.Minute, time.Now)
	addr, _ := startPairingServer(t, db, book)
	invite, err := book.Mint()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PairAsReplica(pairCtx(t), addr, newIdentity(t), invite.Code, acceptAny, &fakeState{}); err != nil {
		t.Fatalf("first pairing: %v", err)
	}

	second := newIdentity(t)
	_, err = PairAsReplica(pairCtx(t), addr, second, invite.Code, acceptAny, &fakeState{})
	if err == nil {
		t.Fatal("PairAsReplica reused a code that was already redeemed")
	}
	if unknown := unknownCodeError(t, addr); err.Error() != unknown {
		t.Fatalf("spent code error = %q, want the same refusal as an unknown code %q", err, unknown)
	}
	if _, err := db.Peer(second.NodeID); err == nil {
		t.Fatal("primary pinned a peer that presented a spent code")
	}
}

func TestPairingRejectsExpiredCode(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	db := newPeerStore(t)
	book := NewInviteBook(time.Minute, func() time.Time { return clock() })
	addr, _ := startPairingServer(t, db, book)
	invite, err := book.Mint()
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)

	replica := newIdentity(t)
	_, err = PairAsReplica(pairCtx(t), addr, replica, invite.Code, acceptAny, &fakeState{})
	if err == nil {
		t.Fatal("PairAsReplica redeemed an expired code")
	}
	if unknown := unknownCodeError(t, addr); err.Error() != unknown {
		t.Fatalf("expired code error = %q, want the same refusal as an unknown code %q", err, unknown)
	}
	if _, err := db.Peer(replica.NodeID); err == nil {
		t.Fatal("primary pinned a peer that presented an expired code")
	}
}

// Pairing is the only route an unpinned peer may reach.
func TestUnpinnedPeerReachesPairButNotVersion(t *testing.T) {
	db := newPeerStore(t)
	book := NewInviteBook(time.Minute, time.Now)
	addr, primaryFP := startPairingServer(t, db, book)
	replica := newIdentity(t)

	if resp := rawDo(t, addr, replica, primaryFP, http.MethodGet, "/replica/version"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("GET /replica/version before pairing = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}

	invite, err := book.Mint()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PairAsReplica(pairCtx(t), addr, replica, invite.Code, acceptAny, &fakeState{}); err != nil {
		t.Fatalf("PairAsReplica from an unpinned peer: %v", err)
	}

	if resp := rawDo(t, addr, replica, primaryFP, http.MethodGet, "/replica/version"); resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /replica/version after pairing = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}
