package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yoshiofthewire/kydns-server/internal/replica"
)

// newJoiner is the replica's half of pairing as the daemon wires it.
func newJoiner(t *testing.T, dir string) *replicaJoiner {
	t.Helper()
	id, err := replica.LoadOrCreateIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	return &replicaJoiner{st: openDB(t, dir), id: id}
}

func joinCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// The two calls the CLI makes, against a real listener: the peek reports the
// key, and the join sends the code only after being handed that same key back.
func TestJoinerPeeksThenPairs(t *testing.T) {
	primaryDir, _ := nodeDir(t, "primary")
	joinerDir, joinerID := nodeDir(t, "joiner")
	admin, primaryID, addr := startPrimaryListener(t, primaryDir)
	j := newJoiner(t, joinerDir)

	fp, err := j.Peek(joinCtx(t), addr)
	if err != nil {
		t.Fatalf("Peek: %v", err)
	}
	if fp != primaryID.NodeID {
		t.Fatalf("Peek = %q, want the primary's key %q", fp, primaryID.NodeID)
	}
	// A peek pairs with nobody: the operator has not confirmed anything yet.
	if _, err := admin.st.Peer(joinerID); err == nil {
		t.Fatal("the peek enrolled this node on the primary")
	}

	code, _, err := admin.Invite()
	if err != nil {
		t.Fatal(err)
	}
	got, err := j.Join(joinCtx(t), addr, code, fp)
	if err != nil {
		t.Fatalf("Join: %v", err)
	}
	if got != primaryID.NodeID {
		t.Fatalf("Join = %q, want %q", got, primaryID.NodeID)
	}
	if _, err := admin.st.Peer(joinerID); err != nil {
		t.Fatalf("the joined node is not pinned on the primary: %v", err)
	}
	// replica_state is what the puller reads on the next start.
	primary, version, err := j.st.ReplicaState()
	if err != nil {
		t.Fatal(err)
	}
	if primary != primaryID.NodeID || version != 0 {
		t.Fatalf("replica_state = %q at version %d, want %q at 0", primary, version, primaryID.NodeID)
	}
}

// If the join reached a different peer than the peek did, the confirmed
// fingerprint no longer matches and the code is never sent. The failure mode
// is a refused pairing, never a silent one.
func TestJoinerRefusesAPeerTheOperatorNeverConfirmed(t *testing.T) {
	primaryDir, _ := nodeDir(t, "primary")
	otherDir, _ := nodeDir(t, "other")
	joinerDir, joinerID := nodeDir(t, "joiner")
	admin, _, addr := startPrimaryListener(t, primaryDir)
	other, _, otherAddr := startPrimaryListener(t, otherDir)
	j := newJoiner(t, joinerDir)

	code, _, err := admin.Invite()
	if err != nil {
		t.Fatal(err)
	}
	// The fingerprint the operator confirmed belongs to a node that is not the
	// one this join dials.
	confirmed, err := j.Peek(joinCtx(t), addr)
	if err != nil {
		t.Fatal(err)
	}
	_, err = j.Join(joinCtx(t), otherAddr, code, confirmed)
	if !errors.Is(err, replica.ErrFingerprintRejected) {
		t.Fatalf("Join error = %v, want ErrFingerprintRejected", err)
	}
	// Neither node heard the code: not the one that was dialled, and not the
	// one whose key was confirmed.
	if _, err := other.st.Peer(joinerID); err == nil {
		t.Fatal("the peer that answered enrolled this node despite the mismatch")
	}
	if _, err := admin.st.Peer(joinerID); err == nil {
		t.Fatal("the refused join enrolled this node anyway")
	}
	if primary, _, err := j.st.ReplicaState(); err != nil || primary != "" {
		t.Fatalf("replica_state = %q, %v after a refused join, want empty", primary, err)
	}
}
