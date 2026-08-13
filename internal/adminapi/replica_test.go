package adminapi

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/yoshiofthewire/kydns-server/internal/registry"
	"github.com/yoshiofthewire/kydns-server/internal/store"
)

// newReplicaAPI is newAPI plus a canned replication status, so a test can
// assert what the endpoint renders without a real Puller.
func newReplicaAPI(t *testing.T, status ReplicaStatus) (http.Handler, string) {
	t.Helper()
	return newReplicaAPICallback(t, func() ReplicaStatus { return status })
}

// newReplicaAPICallback is newReplicaAPI where the status can change between
// requests, so a test can promote a node mid-flight.
func newReplicaAPICallback(t *testing.T, status func() ReplicaStatus) (http.Handler, string) {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "kydns.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	reg := registry.New(s, "home.arpa.", func() error { return nil })
	tok, err := reg.CreateToken("test")
	if err != nil {
		t.Fatal(err)
	}
	api := NewAPI(reg, nil, nil).WithReplication(status)
	return api.Handler(), tok
}

func TestReplicaStatusRequiresAuth(t *testing.T) {
	h, _ := newAPI(t)
	if rec := do(t, h, "GET", "/api/v1/replica/status", "", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET /replica/status without a token = %d, want 401", rec.Code)
	}
}

func TestReplicaStatusStandalone(t *testing.T) {
	h, tok := newReplicaAPI(t, ReplicaStatus{Role: "standalone"})
	rec := do(t, h, "GET", "/api/v1/replica/status", tok, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /replica/status = %d: %s", rec.Code, rec.Body)
	}
	var got ReplicaStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Role != "standalone" || got.PrimaryAddr != "" || got.PrimaryNodeID != "" {
		t.Fatalf("got %+v, want a bare standalone status", got)
	}
}

func TestReplicaStatusReplica(t *testing.T) {
	want := ReplicaStatus{
		Role: "replica", PrimaryAddr: "10.0.0.2:8443", PrimaryNodeID: "fp",
		LastSyncUnix: 1234, LastVersion: 5, Stale: true,
	}
	h, tok := newReplicaAPI(t, want)
	rec := do(t, h, "GET", "/api/v1/replica/status", tok, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /replica/status = %d: %s", rec.Code, rec.Body)
	}
	var got ReplicaStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}
