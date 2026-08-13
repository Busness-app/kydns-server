package adminapi

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/yoshiofthewire/kydns-server/internal/replica"
)

const (
	peerFP  = "1a2b3c4d5e6f70819200aabbccddeeff1a2b3c4d5e6f70819200aabbccddeeff"
	otherFP = "99887766554433221100ffeeddccbbaa99887766554433221100ffeeddccbbaa"
)

// fakeJoiner stands in for the replica package's half. Peek has nowhere to put
// a code, which is the property under test made structural.
type fakeJoiner struct {
	presented  string
	peeked     []string
	joinedTo   []string
	joinedCode []string
	joinErr    error
}

func (j *fakeJoiner) Peek(_ context.Context, address string) (string, error) {
	j.peeked = append(j.peeked, address)
	return j.presented, nil
}

func (j *fakeJoiner) Join(_ context.Context, address, code, fingerprint string) (string, error) {
	j.joinedTo = append(j.joinedTo, address)
	j.joinedCode = append(j.joinedCode, code)
	if j.joinErr != nil {
		return "", j.joinErr
	}
	if fingerprint != j.presented {
		return "", fmt.Errorf("%w: %s presented %s", replica.ErrFingerprintRejected, address, j.presented)
	}
	return j.presented, nil
}

// joinerAPI is a node being paired: a replica by role, since that is where
// these two calls are used.
func joinerAPI(t *testing.T) (*API, *fakeJoiner, string) {
	t.Helper()
	api, tok := newAPIWithStatus(t, func() ReplicaStatus {
		return ReplicaStatus{Role: "replica", PrimaryAddr: "10.0.0.2:8443"}
	})
	j := &fakeJoiner{presented: peerFP}
	return api.WithReplicaJoiner(j), j, tok
}

// The peek reports the key the peer presented and sends nothing else. The code
// travels on the second call, after the operator has confirmed this one.
func TestPeekReportsTheFingerprintAndSendsNoCode(t *testing.T) {
	api, j, tok := joinerAPI(t)

	rec := do(t, api.Handler(), "POST", PathReplicaPairPeek, tok, `{"address":"10.0.0.2:8443","code":"K7QP2M9XTV4RB3ZC"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST %s = %d: %s", PathReplicaPairPeek, rec.Code, rec.Body)
	}
	var got struct {
		Fingerprint string `json:"fingerprint"`
	}
	decodeInto(t, rec, &got)
	if got.Fingerprint != peerFP {
		t.Errorf("fingerprint = %q, want the key the peer presented %q", got.Fingerprint, peerFP)
	}
	if len(j.peeked) != 1 {
		t.Fatalf("peeked %q, want one dial", j.peeked)
	}
	if len(j.joinedCode) != 0 {
		t.Fatalf("the peek sent codes %q; a peek pairs with nobody", j.joinedCode)
	}
}

// A join with no confirmed fingerprint is the prompt-free default that must
// not exist. It is refused before anything is dialled.
func TestJoinWithoutAConfirmedFingerprintIsRefused(t *testing.T) {
	api, j, tok := joinerAPI(t)

	for _, body := range []string{
		`{"address":"10.0.0.2:8443","code":"K7QP2M9XTV4RB3ZC"}`,
		`{"address":"10.0.0.2:8443","code":"K7QP2M9XTV4RB3ZC","fingerprint":"  "}`,
	} {
		rec := do(t, api.Handler(), "POST", PathReplicaJoin, tok, body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("POST %s with %s = %d, want 400: %s", PathReplicaJoin, body, rec.Code, rec.Body)
		}
	}
	if len(j.joinedCode) != 0 {
		t.Fatalf("codes %q were sent for a join that confirmed no key", j.joinedCode)
	}
}

func TestJoinPassesTheConfirmedFingerprintThrough(t *testing.T) {
	api, j, tok := joinerAPI(t)

	body := fmt.Sprintf(`{"address":"10.0.0.2:8443","code":"K7QP2M9XTV4RB3ZC","fingerprint":%q}`, peerFP)
	rec := do(t, api.Handler(), "POST", PathReplicaJoin, tok, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST %s = %d: %s", PathReplicaJoin, rec.Code, rec.Body)
	}
	var got struct {
		PrimaryNodeID string `json:"primary_node_id"`
	}
	decodeInto(t, rec, &got)
	if got.PrimaryNodeID != peerFP {
		t.Errorf("primary_node_id = %q, want %q", got.PrimaryNodeID, peerFP)
	}
	if len(j.joinedCode) != 1 || j.joinedCode[0] != "K7QP2M9XTV4RB3ZC" {
		t.Fatalf("joined with codes %q, want the one the operator supplied", j.joinedCode)
	}
}

// If the peek and the join reached different peers, the join's own comparison
// is what catches it. The answer must be its own error code, because it reads
// nothing like a dial that failed.
func TestJoinReportsAFingerprintMismatchDistinctly(t *testing.T) {
	api, _, tok := joinerAPI(t)

	body := fmt.Sprintf(`{"address":"10.0.0.2:8443","code":"K7QP2M9XTV4RB3ZC","fingerprint":%q}`, otherFP)
	rec := do(t, api.Handler(), "POST", PathReplicaJoin, tok, body)
	if rec.Code != http.StatusConflict {
		t.Fatalf("POST %s with a mismatch = %d, want 409: %s", PathReplicaJoin, rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "fingerprint_mismatch") {
		t.Errorf("a mismatch is not reported under its own code: %s", rec.Body)
	}

	api2, j2, tok2 := joinerAPI(t)
	j2.joinErr = fmt.Errorf("dial 10.0.0.2:8443: connection refused")
	rec2 := do(t, api2.Handler(), "POST", PathReplicaJoin, tok2, body)
	if rec2.Code != http.StatusBadGateway {
		t.Fatalf("POST %s with a dead peer = %d, want 502: %s", PathReplicaJoin, rec2.Code, rec2.Body)
	}
	if strings.Contains(rec2.Body.String(), "fingerprint_mismatch") {
		t.Errorf("a dial failure is reported as a mismatch: %s", rec2.Body)
	}
}

// Pairing is how a node becomes a replica, so both calls have to survive the
// write gate. They are still writes to everyone else.
func TestJoinRoutesAreReachableOnAReplicaAndNeedAuth(t *testing.T) {
	api, _, tok := joinerAPI(t)
	h := api.Handler()

	for _, p := range []string{PathReplicaPairPeek, PathReplicaJoin} {
		rec := do(t, h, "POST", p, tok, `{"address":"10.0.0.2:8443","code":"c","fingerprint":"`+peerFP+`"}`)
		if strings.Contains(rec.Body.String(), "read_only_replica") {
			t.Errorf("POST %s on a replica was refused by the write gate: %s", p, rec.Body)
		}
		if rec := do(t, h, "POST", p, "", "{}"); rec.Code != http.StatusUnauthorized {
			t.Errorf("POST %s without a token = %d, want 401", p, rec.Code)
		}
	}
}

// A node with no replication wired has no identity to pair with. It says so
// rather than reporting a pairing that never happened.
func TestJoinWithoutReplicationWired(t *testing.T) {
	h, tok := newAPI(t)
	for _, p := range []string{PathReplicaPairPeek, PathReplicaJoin} {
		rec := do(t, h, "POST", p, tok, `{"address":"10.0.0.2:8443","code":"c","fingerprint":"`+peerFP+`"}`)
		if rec.Code != http.StatusConflict {
			t.Errorf("POST %s with no replication = %d, want 409: %s", p, rec.Code, rec.Body)
		}
		if !strings.Contains(rec.Body.String(), "replication") {
			t.Errorf("POST %s does not explain itself: %s", p, rec.Body)
		}
	}
}
