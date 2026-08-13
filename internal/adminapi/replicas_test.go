package adminapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yoshiofthewire/kydns-server/internal/registry"
	"github.com/yoshiofthewire/kydns-server/internal/replica"
	"github.com/yoshiofthewire/kydns-server/internal/store"
)

// testAdmin is the primary's half backed by the real store and the real invite
// book, so the handlers are exercised against the objects the daemon hands
// them rather than a hand-rolled stand-in.
type testAdmin struct {
	st   *store.Store
	book *replica.InviteBook
}

func (a *testAdmin) Invite() (string, time.Time, error) {
	if a.book == nil {
		return "", time.Time{}, ErrNotServingReplicas
	}
	inv, err := a.book.Mint()
	return inv.Code, inv.ExpiresAt, err
}

func (a *testAdmin) Peers() ([]store.Peer, error)  { return a.st.Peers() }
func (a *testAdmin) Unpair(nodeID string) error    { return a.st.DeletePeer(nodeID) }
func (a *testAdmin) ConfigVersion() (int64, error) { return a.st.ConfigVersion() }

// primaryAPI is a node serving replicas: a real store, a real book, and a
// status reporting this node's own fingerprint.
func primaryAPI(t *testing.T, nodeID string) (*API, *testAdmin, string) {
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
	admin := &testAdmin{st: s, book: replica.NewInviteBook(10*time.Minute, time.Now)}
	api := NewAPI(reg, nil, nil).
		WithReplication(func() ReplicaStatus { return ReplicaStatus{Role: "primary", NodeID: nodeID} }).
		WithReplicaAdmin(admin)
	return api, admin, tok
}

func decodeInto(t *testing.T, rec *httptest.ResponseRecorder, v any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), v); err != nil {
		t.Fatalf("decode %s: %v", rec.Body, err)
	}
}

// The operator confirms the primary's key on the replica before sending the
// code. An invite that carries only a code leaves them nothing to compare
// against, so both must come back from the one call.
func TestInviteReturnsCodeAndFingerprint(t *testing.T) {
	const nodeID = "aa11bb22cc33dd44ee55ff6600778899aa11bb22cc33dd44ee55ff6600778899"
	api, admin, tok := primaryAPI(t, nodeID)

	rec := do(t, api.Handler(), "POST", "/api/v1/replicas/invite", tok, "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /replicas/invite = %d: %s", rec.Code, rec.Body)
	}
	var got struct {
		Code      string `json:"code"`
		NodeID    string `json:"node_id"`
		ExpiresAt int64  `json:"expires_at"`
	}
	decodeInto(t, rec, &got)

	if got.Code == "" {
		t.Error("no pairing code in the invite")
	}
	// Not merely non-empty: the operator compares this against what the replica
	// sees the primary present, so it must be this node's own key.
	if got.NodeID != nodeID {
		t.Errorf("node_id = %q, want this node's fingerprint %q", got.NodeID, nodeID)
	}
	if got.ExpiresAt <= time.Now().Unix() {
		t.Errorf("expires_at = %d, want a time in the future", got.ExpiresAt)
	}
	// The code came off the book the listener redeems against, not a fresh one.
	if !admin.book.Redeem(got.Code) {
		t.Error("the minted code is not outstanding on the invite book")
	}
}

// Minting is a write. A replica must be sent to its primary, and must not be
// added to the write gate's exempt set to get there.
func TestInviteIsRefusedOnAReplica(t *testing.T) {
	const primary = "10.0.0.2:8443"
	api, _, tok := primaryAPI(t, "fp")
	// The same API, now reporting itself a replica: only the role changes.
	api = api.WithReplication(func() ReplicaStatus {
		return ReplicaStatus{Role: "replica", PrimaryAddr: primary}
	})
	rec := do(t, api.Handler(), "POST", "/api/v1/replicas/invite", tok, "")
	if rec.Code != http.StatusConflict {
		t.Fatalf("POST /replicas/invite on a replica = %d, want 409: %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), primary) {
		t.Errorf("refusal does not name the primary to go to: %s", rec.Body)
	}
	if writeExempt["/api/v1/replicas/invite"] {
		t.Error("the invite route is in the write gate's exempt set; a replica must not mint invites")
	}
}

// Removing a replica is a write too.
func TestRemoveReplicaIsRefusedOnAReplica(t *testing.T) {
	api, _, tok := primaryAPI(t, "fp")
	api = api.WithReplication(func() ReplicaStatus {
		return ReplicaStatus{Role: "replica", PrimaryAddr: "10.0.0.2:8443"}
	})
	if rec := do(t, api.Handler(), "DELETE", "/api/v1/replicas/fp-1", tok, ""); rec.Code != http.StatusConflict {
		t.Fatalf("DELETE /replicas/fp-1 on a replica = %d, want 409: %s", rec.Code, rec.Body)
	}
}

func TestReplicaRoutesRequireAuth(t *testing.T) {
	api, _, _ := primaryAPI(t, "fp")
	h := api.Handler()
	for _, r := range [][2]string{
		{"POST", "/api/v1/replicas/invite"},
		{"GET", "/api/v1/replicas"},
		{"DELETE", "/api/v1/replicas/fp-1"},
	} {
		if rec := do(t, h, r[0], r[1], "", ""); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s without a token = %d, want 401", r[0], r[1], rec.Code)
		}
	}
}

// Lag is what tells an operator a replica has stopped following. It is the
// primary's current version minus the one the peer last reported, so it has to
// be computed from both and never reported as a flat zero.
func TestListReplicasReportsLagAndLastSync(t *testing.T) {
	api, admin, tok := primaryAPI(t, "fp-primary")

	// Real writes, so the version the peers lag behind is a real one.
	for _, name := range []string{"a", "b", "c"} {
		if _, err := admin.st.PutService(store.Service{
			Name: name, Addresses: []store.Address{{Address: "192.168.1.10"}},
		}); err != nil {
			t.Fatal(err)
		}
	}
	version, err := admin.st.ConfigVersion()
	if err != nil {
		t.Fatal(err)
	}
	if version < 2 {
		t.Fatalf("config version = %d; the fixture is not producing a version to lag behind", version)
	}

	for _, p := range []store.Peer{
		{NodeID: "fp-current", Label: "kitchen", PairedAt: 10},
		{NodeID: "fp-behind", Label: "attic", PairedAt: 10},
		{NodeID: "fp-never", Label: "shed", PairedAt: 10},
	} {
		if err := admin.st.PairPeer(p); err != nil {
			t.Fatal(err)
		}
	}
	behind := version - 2
	if err := admin.st.TouchPeer("fp-current", 1700, &version); err != nil {
		t.Fatal(err)
	}
	if err := admin.st.TouchPeer("fp-behind", 1600, &behind); err != nil {
		t.Fatal(err)
	}

	rec := do(t, api.Handler(), "GET", "/api/v1/replicas", tok, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /replicas = %d: %s", rec.Code, rec.Body)
	}
	var got struct {
		ConfigVersion int64 `json:"config_version"`
		Replicas      []struct {
			NodeID      string `json:"node_id"`
			Label       string `json:"label"`
			LastSyncAt  int64  `json:"last_sync_at"`
			LastVersion int64  `json:"last_version"`
			Lag         int64  `json:"lag"`
			Status      string `json:"status"`
		} `json:"replicas"`
	}
	decodeInto(t, rec, &got)
	if got.ConfigVersion != version {
		t.Errorf("config_version = %d, want %d", got.ConfigVersion, version)
	}
	if len(got.Replicas) != 3 {
		t.Fatalf("listed %d replicas, want 3: %s", len(got.Replicas), rec.Body)
	}
	rows := map[string]int{}
	for i, r := range got.Replicas {
		rows[r.NodeID] = i
	}
	for _, want := range []struct {
		nodeID   string
		label    string
		lastSync int64
		lag      int64
		status   string
	}{
		{"fp-current", "kitchen", 1700, 0, "in_sync"},
		{"fp-behind", "attic", 1600, 2, "behind"},
		{"fp-never", "shed", 0, version, "never_synced"},
	} {
		i, ok := rows[want.nodeID]
		if !ok {
			t.Errorf("%s is missing from the list", want.nodeID)
			continue
		}
		r := got.Replicas[i]
		if r.Label != want.label || r.LastSyncAt != want.lastSync || r.Lag != want.lag || r.Status != want.status {
			t.Errorf("%s = %+v, want label %q last_sync %d lag %d status %q",
				want.nodeID, r, want.label, want.lastSync, want.lag, want.status)
		}
	}
}

// A node with replication wired but no listener has no book to mint from. It
// must say so rather than hand back an empty code an operator would type in.
func TestInviteWithoutAReplicationListener(t *testing.T) {
	api, admin, tok := primaryAPI(t, "fp")
	admin.book = nil
	rec := do(t, api.Handler(), "POST", "/api/v1/replicas/invite", tok, "")
	if rec.Code != http.StatusConflict {
		t.Fatalf("POST /replicas/invite with no listener = %d, want 409: %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "replication") {
		t.Errorf("refusal does not explain itself: %s", rec.Body)
	}
}

// A node with no replication wired at all still answers the list, empty: the
// screen is reachable everywhere and says "none" rather than erroring.
func TestListReplicasWithoutReplicationIsEmpty(t *testing.T) {
	h, tok := newAPI(t)
	rec := do(t, h, "GET", "/api/v1/replicas", tok, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /replicas with no replication = %d: %s", rec.Code, rec.Body)
	}
	var got struct {
		Replicas []map[string]any `json:"replicas"`
	}
	decodeInto(t, rec, &got)
	if len(got.Replicas) != 0 {
		t.Fatalf("listed %d replicas on a node with no replication", len(got.Replicas))
	}
}

func TestRemoveReplicaDeletesThePeer(t *testing.T) {
	api, admin, tok := primaryAPI(t, "fp-primary")
	if err := admin.st.PairPeer(store.Peer{NodeID: "fp-1", Label: "attic"}); err != nil {
		t.Fatal(err)
	}
	if rec := do(t, api.Handler(), "DELETE", "/api/v1/replicas/fp-1", tok, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE /replicas/fp-1 = %d: %s", rec.Code, rec.Body)
	}
	if peers, err := admin.st.Peers(); err != nil || len(peers) != 0 {
		t.Fatalf("Peers() = %v, %v after removal, want empty", peers, err)
	}
	// A second removal is a 404, not a silent success: the operator asked about
	// a node this one does not serve.
	if rec := do(t, api.Handler(), "DELETE", "/api/v1/replicas/fp-1", tok, ""); rec.Code != http.StatusNotFound {
		t.Fatalf("DELETE of an unknown replica = %d, want 404", rec.Code)
	}
}
