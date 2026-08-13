package store

import (
	"errors"
	"testing"
)

func TestPeerRoundTrip(t *testing.T) {
	s := open(t)
	p := Peer{NodeID: "fp-1", Label: "pi", Address: "192.168.1.9:8443", PairedAt: 100}
	if err := s.PutPeer(p); err != nil {
		t.Fatal(err)
	}
	got, err := s.Peer("fp-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Label != "pi" || got.Address != "192.168.1.9:8443" {
		t.Fatalf("Peer() = %+v, want the stored values", got)
	}
}

func TestPeerNotFound(t *testing.T) {
	s := open(t)
	if _, err := s.Peer("nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Peer() error = %v, want ErrNotFound", err)
	}
}

func TestDeletePeerRemovesIt(t *testing.T) {
	s := open(t)
	if err := s.PutPeer(Peer{NodeID: "fp-1"}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeletePeer("fp-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Peer("fp-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Peer() error = %v after delete, want ErrNotFound", err)
	}
}

// The peer list is this node's own. Replicating it would make a primary
// rewrite its replicas' trust anchors.
func TestPeerWriteDoesNotBumpConfigVersion(t *testing.T) {
	s := open(t)
	before, err := s.ConfigVersion()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutPeer(Peer{NodeID: "fp-1"}); err != nil {
		t.Fatal(err)
	}
	after, err := s.ConfigVersion()
	if err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("ConfigVersion() = %d after a peer write, want %d", after, before)
	}
}

func TestReplicaStateRoundTrip(t *testing.T) {
	s := open(t)
	nodeID, version, err := s.ReplicaState()
	if err != nil {
		t.Fatal(err)
	}
	if nodeID != "" || version != 0 {
		t.Fatalf("ReplicaState() = %q/%d on a fresh database, want empty/0", nodeID, version)
	}
	if err := s.SetReplicaState("fp-primary", 42); err != nil {
		t.Fatal(err)
	}
	nodeID, version, err = s.ReplicaState()
	if err != nil {
		t.Fatal(err)
	}
	if nodeID != "fp-primary" || version != 42 {
		t.Fatalf("ReplicaState() = %q/%d, want fp-primary/42", nodeID, version)
	}
}

// Re-pairing zeroes the peer row; the applied version must not go with it.
func TestReplicaStateSurvivesRePairing(t *testing.T) {
	s := open(t)
	if err := s.SetReplicaState("fp-primary", 42); err != nil {
		t.Fatal(err)
	}
	if err := s.PutPeer(Peer{NodeID: "fp-primary", Address: "10.0.0.2:8443"}); err != nil {
		t.Fatal(err)
	}
	if _, version, _ := s.ReplicaState(); version != 42 {
		t.Fatalf("ReplicaState() version = %d after a re-pair, want 42", version)
	}
}
