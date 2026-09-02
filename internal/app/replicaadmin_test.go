package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Busness-app/kydns-server/internal/replica"
	"github.com/Busness-app/kydns-server/internal/store"
)

// startPrimaryListener runs the real replication listener the way the daemon
// does and hands back the admin surface built on top of it. The invite book is
// reachable only through the server, which is the point: a second book would
// mint codes the listener has never heard of.
func startPrimaryListener(t *testing.T, dir string) (*replicaAdmin, *replica.Identity, string) {
	t.Helper()
	db := openDB(t, dir)
	id, err := replica.LoadOrCreateIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := replica.NewServer(id, db, &storeSource{st: db, nodeID: id.NodeID},
		replica.NewInviteBook(inviteTTL, time.Now))
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return &replicaAdmin{st: db, srv: srv}, id, l.Addr().String()
}

// One book, or an operator types a code the listener will never recognise and
// has no way to tell that from a typo.
func TestAPIInviteIsRedeemableByThePairingEndpoint(t *testing.T) {
	primaryDir, _ := nodeDir(t, "primary")
	joinerDir, joinerID := nodeDir(t, "joiner")
	admin, primaryID, addr := startPrimaryListener(t, primaryDir)

	code, expires, err := admin.Invite()
	if err != nil {
		t.Fatal(err)
	}
	if code == "" || !expires.After(time.Now()) {
		t.Fatalf("Invite() = %q expiring %v, want a live code", code, expires)
	}

	joiner, err := replica.LoadOrCreateIdentity(joinerDir)
	if err != nil {
		t.Fatal(err)
	}
	joinerDB, err := store.Open(filepath.Join(joinerDir, "kydns.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { joinerDB.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// The operator compares the fingerprint the invite printed against the key
	// the primary presents; only a match sends the code.
	got, err := replica.PairAsReplica(ctx, addr, joiner, code,
		func(_ context.Context, fp string) (bool, error) { return fp == primaryID.NodeID, nil },
		joinerDB)
	if err != nil {
		t.Fatalf("pairing with a code minted through the admin API failed: %v", err)
	}
	if got != primaryID.NodeID {
		t.Fatalf("paired with %q, want the primary %q", got, primaryID.NodeID)
	}
	if _, err := admin.st.Peer(joinerID); err != nil {
		t.Fatalf("the joined node is not pinned on the primary: %v", err)
	}
}

// A spent code is spent everywhere: minting through the API must not leave a
// second copy outstanding on some other book.
func TestAPIInviteIsSingleUse(t *testing.T) {
	primaryDir, _ := nodeDir(t, "primary")
	joinerDir, _ := nodeDir(t, "joiner")
	secondDir, _ := nodeDir(t, "second")
	admin, primaryID, addr := startPrimaryListener(t, primaryDir)

	code, _, err := admin.Invite()
	if err != nil {
		t.Fatal(err)
	}
	confirm := func(_ context.Context, fp string) (bool, error) { return fp == primaryID.NodeID, nil }
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for _, dir := range []string{joinerDir, secondDir} {
		id, err := replica.LoadOrCreateIdentity(dir)
		if err != nil {
			t.Fatal(err)
		}
		db, err := store.Open(filepath.Join(dir, "kydns.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		_, err = replica.PairAsReplica(ctx, addr, id, code, confirm, db)
		if dir == joinerDir && err != nil {
			t.Fatalf("the first use of the code failed: %v", err)
		}
		if dir == secondDir && err == nil {
			t.Fatal("the same invite paired a second node; the code is not being consumed")
		}
	}
}

// Removing a replica has to stop it pulling, not just take it off a screen.
func TestRemoveReplicaUnpins(t *testing.T) {
	primaryDir, _ := nodeDir(t, "primary")
	peerDir, peerID := nodeDir(t, "peer")
	admin, primaryID, addr := startPrimaryListener(t, primaryDir)

	if err := admin.st.PutSettings(store.Settings{PrivateDomain: "home.arpa."}); err != nil {
		t.Fatal(err)
	}
	if err := admin.st.PairPeer(store.Peer{NodeID: peerID, Label: "attic", PairedAt: time.Now().Unix()}); err != nil {
		t.Fatal(err)
	}

	peer, err := replica.LoadOrCreateIdentity(peerDir)
	if err != nil {
		t.Fatal(err)
	}
	client, err := replica.NewClient(addr, peer, primaryID.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Paired: it pulls. Without this the refusal below proves nothing.
	if _, err := client.Version(ctx, 0); err != nil {
		t.Fatalf("a paired replica could not read a version: %v", err)
	}

	if err := admin.Unpair(peerID); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.st.Peer(peerID); err == nil {
		t.Fatal("the peer row survived removal")
	}

	// A fresh client, so the answer cannot come from a connection authorised
	// before the removal.
	after, err := replica.NewClient(addr, peer, primaryID.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	defer after.Close()
	if _, err := after.Version(ctx, 0); err == nil {
		t.Fatal("a removed replica still pulled from the listener")
	} else if !strings.Contains(err.Error(), "403") && !strings.Contains(err.Error(), "orbidden") {
		t.Errorf("a removed replica was turned away with %v, want a forbidden", err)
	}
}

// apiJSON sends an authenticated admin request and decodes the reply.
func apiJSON(t *testing.T, method, url, token string, out any) int {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			t.Fatalf("%s %s returned %s: %v", method, url, raw, err)
		}
	}
	return resp.StatusCode
}

// The status endpoint's node_id has been defined and empty since Task 1. It is
// the key an operator confirms when pairing, so a live primary must report its
// own, and the invite it mints must carry the same one.
func TestPrimaryReportsItsFingerprintAndMintsInvitesWithIt(t *testing.T) {
	dir, nodeID := nodeDir(t, "primary")
	replAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	cfg, _, adminPort := writeConfig(t, dir, fmt.Sprintf("replication:\n  listen: %q\n", replAddr))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go Serve(ctx, cfg, nil)

	base := fmt.Sprintf("http://127.0.0.1:%d", adminPort)
	waitForHTTP(t, base+"/api/v1/healthz")
	token := waitForFile(t, filepath.Join(dir, "bootstrap-token"))

	var status struct {
		Role   string `json:"role"`
		NodeID string `json:"node_id"`
	}
	if code := apiJSON(t, "GET", base+"/api/v1/replica/status", token, &status); code != http.StatusOK {
		t.Fatalf("GET /replica/status = %d", code)
	}
	if status.Role != "primary" {
		t.Fatalf("role = %q, want primary", status.Role)
	}
	if status.NodeID == "" {
		t.Fatal("node_id is empty on a node with replication enabled; nothing can be confirmed at pairing")
	}
	if status.NodeID != nodeID {
		t.Fatalf("node_id = %q, want this node's identity %q", status.NodeID, nodeID)
	}

	var invite struct {
		Code   string `json:"code"`
		NodeID string `json:"node_id"`
	}
	if code := apiJSON(t, "POST", base+"/api/v1/replicas/invite", token, &invite); code != http.StatusCreated {
		t.Fatalf("POST /replicas/invite = %d", code)
	}
	if invite.Code == "" {
		t.Error("the invite carries no pairing code")
	}
	if invite.NodeID != nodeID {
		t.Errorf("the invite names %q, want this node's fingerprint %q", invite.NodeID, nodeID)
	}
}

// Invite is the only place the fingerprint reaches the operator, so a node with
// no listener must refuse rather than hand back a code nothing can redeem.
func TestInviteWithoutAListenerRefuses(t *testing.T) {
	dir := t.TempDir()
	admin := &replicaAdmin{st: openDB(t, dir)}
	if _, _, err := admin.Invite(); err == nil {
		t.Fatal("Invite() succeeded on a node that serves no replicas")
	}
}
