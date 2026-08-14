package adminapi

import (
	"encoding/json"
	"net/http"
	"testing"
)

// fakePromoter answers what this node's own promotion would, and counts the
// calls: a handler that never reached it would otherwise pass every status
// assertion below.
type fakePromoter struct {
	calls   int
	changed bool
}

func (p *fakePromoter) Promote() (bool, error) {
	p.calls++
	return p.changed, nil
}

// promoteReply is the decoded body, so no assertion here can be satisfied by
// the word "primary" appearing somewhere else in the JSON.
type promoteReply struct {
	Role     string `json:"role"`
	Promoted bool   `json:"promoted"`
}

func promoteAPI(t *testing.T, role string, p ReplicaPromoter) (http.Handler, string) {
	t.Helper()
	api, tok := newAPIWithStatus(t, func() ReplicaStatus {
		return ReplicaStatus{Role: role, PrimaryAddr: "10.0.0.2:8443"}
	})
	return api.WithReplicaPromoter(p).Handler(), tok
}

// The Task 2 exemption, exercised through the real write gate: promotion is
// the operator's escape from a replica, and a replica that cannot be promoted
// is useless in exactly the outage promotion exists for.
func TestPromoteIsAllowedOnAReplica(t *testing.T) {
	p := &fakePromoter{changed: true}
	h, tok := promoteAPI(t, "replica", p)

	rec := do(t, h, "POST", PathReplicaPromote, tok, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("POST %s on a replica = %d: %s", PathReplicaPromote, rec.Code, rec.Body)
	}
	if p.calls != 1 {
		t.Fatalf("the node was promoted %d times, want exactly 1", p.calls)
	}
	var got promoteReply
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Role != "primary" || !got.Promoted {
		t.Fatalf("reply = %+v, want a promoted primary", got)
	}
}

// Nothing to do is not a failure. An operator promoting the node they are
// already on, or re-running the command after a timeout, must not be told
// something went wrong.
func TestPromoteOnAPrimaryIsANoOpNotAnError(t *testing.T) {
	p := &fakePromoter{changed: false}
	h, tok := promoteAPI(t, "primary", p)

	rec := do(t, h, "POST", PathReplicaPromote, tok, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("POST %s on a primary = %d: %s", PathReplicaPromote, rec.Code, rec.Body)
	}
	var got promoteReply
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Promoted {
		t.Fatalf("reply = %+v, want promoted false: nothing changed", got)
	}
	if got.Role != "primary" {
		t.Fatalf("role = %q, want primary", got.Role)
	}
}

// The exemption is from the write gate, not from authentication. A stranger
// who could promote this node could take it away from its primary.
func TestPromoteRequiresAuth(t *testing.T) {
	p := &fakePromoter{changed: true}
	h, _ := promoteAPI(t, "replica", p)

	if rec := do(t, h, "POST", PathReplicaPromote, "", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous POST %s = %d, want 401", PathReplicaPromote, rec.Code)
	}
	if p.calls != 0 {
		t.Fatalf("an anonymous caller promoted the node %d times", p.calls)
	}
}

// An API built without the promoter has nothing to flip, and says so rather
// than reporting a success that changed nothing.
func TestPromoteWithoutAPromoterRefuses(t *testing.T) {
	api, tok := newAPIWithStatus(t, func() ReplicaStatus { return ReplicaStatus{Role: "replica"} })
	if rec := do(t, api.Handler(), "POST", PathReplicaPromote, tok, ""); rec.Code != http.StatusConflict {
		t.Fatalf("POST %s with no promoter wired = %d, want 409", PathReplicaPromote, rec.Code)
	}
}
