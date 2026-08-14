package store

import (
	"errors"
	"testing"
)

func TestPeerRoundTrip(t *testing.T) {
	s := open(t)
	p := Peer{NodeID: "fp-1", Label: "pi", Address: "192.168.1.9:8443", PairedAt: 100}
	if err := s.PairPeer(p); err != nil {
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
	if err := s.PairPeer(Peer{NodeID: "fp-1"}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeletePeer("fp-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Peer("fp-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Peer() error = %v after delete, want ErrNotFound", err)
	}
}

// A peer that reports the version it holds records it; one that reports
// nothing still records that it was seen, and keeps the version it last named.
func TestTouchPeerRecordsTheReportedVersion(t *testing.T) {
	s := open(t)
	if err := s.PairPeer(Peer{NodeID: "fp-1"}); err != nil {
		t.Fatal(err)
	}
	seven := int64(7)
	if err := s.TouchPeer("fp-1", 100, &seven); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Peer("fp-1"); got.LastVersion != 7 || got.LastSyncAt != 100 {
		t.Fatalf("Peer() = %+v, want version 7 seen at 100", got)
	}

	if err := s.TouchPeer("fp-1", 200, nil); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Peer("fp-1")
	if got.LastVersion != 7 || got.LastSyncAt != 200 {
		t.Fatalf("Peer() = %+v after a touch reporting nothing, want version 7 seen at 200", got)
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
	if err := s.PairPeer(Peer{NodeID: "fp-1"}); err != nil {
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

// An operator names a peer; re-pairing that node must not take the name back
// off it, nor report a replica that has been syncing for a week as never seen.
// The pairing exchange always sends a generated default label, so preserving
// the operator's one has to be the store's job.
func TestRePairPreservesOperatorLabel(t *testing.T) {
	s := open(t)
	if err := s.PairPeer(Peer{NodeID: "fp-1", Label: "kitchen pi", PairedAt: 100}); err != nil {
		t.Fatal(err)
	}
	seven := int64(7)
	if err := s.TouchPeer("fp-1", 900, &seven); err != nil {
		t.Fatal(err)
	}

	// Exactly what handlePair writes on a re-pair: a default label, no history.
	if err := s.PairPeer(Peer{NodeID: "fp-1", Label: "fp-1", Address: "10.0.0.9:8443", PairedAt: 500}); err != nil {
		t.Fatal(err)
	}

	got, err := s.Peer("fp-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Label != "kitchen pi" {
		t.Errorf("Label = %q after a re-pair, want the operator's %q", got.Label, "kitchen pi")
	}
	if got.LastSyncAt != 900 || got.LastVersion != 7 {
		t.Errorf("sync history = %d/%d after a re-pair, want 900/7", got.LastSyncAt, got.LastVersion)
	}
	// The pairing itself is new, so these are the values that must move.
	if got.PairedAt != 500 || got.Address != "10.0.0.9:8443" {
		t.Errorf("got %+v, want the new pairing time and address", got)
	}
}

// A first pairing takes the label it is given: preserving on re-pair must not
// turn into never writing a label at all.
func TestFirstPairingTakesItsLabel(t *testing.T) {
	s := open(t)
	if err := s.PairPeer(Peer{NodeID: "fp-1", Label: "fp-1"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Peer("fp-1"); got.Label != "fp-1" {
		t.Fatalf("Label = %q on a first pairing, want fp-1", got.Label)
	}
}

// Re-pairing zeroes the peer row; the applied version must not go with it.
func TestReplicaStateSurvivesRePairing(t *testing.T) {
	s := open(t)
	if err := s.SetReplicaState("fp-primary", 42); err != nil {
		t.Fatal(err)
	}
	if err := s.PairPeer(Peer{NodeID: "fp-primary", Address: "10.0.0.2:8443"}); err != nil {
		t.Fatal(err)
	}
	if _, version, _ := s.ReplicaState(); version != 42 {
		t.Fatalf("ReplicaState() version = %d after a re-pair, want 42", version)
	}
}

// A promotion is recorded here rather than by rewriting the operator's config
// file, so this row is the only thing that can tell a restarted node it is no
// longer a replica. Joining a primary clears it again.
func TestPromotionIsRecordedAndCleared(t *testing.T) {
	s := open(t)
	if at, err := s.Promotion(); err != nil || at != 0 {
		t.Fatalf("Promotion() = %d, %v on a node that was never promoted, want 0", at, err)
	}
	const promotedAt = 1786000000
	if err := s.RecordPromotion(promotedAt); err != nil {
		t.Fatal(err)
	}
	if at, err := s.Promotion(); err != nil || at != promotedAt {
		t.Fatalf("Promotion() = %d, %v, want %d", at, err, promotedAt)
	}
	if err := s.ClearPromotion(); err != nil {
		t.Fatal(err)
	}
	if at, err := s.Promotion(); err != nil || at != 0 {
		t.Fatalf("Promotion() = %d, %v after ClearPromotion, want 0", at, err)
	}
}
