package app

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yoshiofthewire/kydns-server/internal/replica"
	"github.com/yoshiofthewire/kydns-server/internal/store"
)

// nodeDir prepares a data dir and returns the node identity the daemon will
// load out of it, so the test can pin it before either process starts.
func nodeDir(t *testing.T, name string) (dir, nodeID string) {
	t.Helper()
	dir = filepath.Join(t.TempDir(), name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	id, err := replica.LoadOrCreateIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	return dir, id.NodeID
}

// openDB opens a node's database the way its daemon will.
func openDB(t *testing.T, dir string) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(dir, "kydns.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// pinPeer writes what the pairing exchange writes on the primary: a replica it
// serves. Pairing has no CLI yet, so the test pairs through the store API.
func pinPeer(t *testing.T, dir string, p store.Peer) {
	t.Helper()
	p.PairedAt = time.Now().Unix()
	if err := openDB(t, dir).PutPeer(p); err != nil {
		t.Fatal(err)
	}
}

// pinPrimary writes what pairing writes on the replica: the one primary it
// follows. That lives in replica_state, not in peers.
func pinPrimary(t *testing.T, dir, nodeID string) {
	t.Helper()
	if err := openDB(t, dir).SetReplicaState(nodeID, 0); err != nil {
		t.Fatal(err)
	}
}

// waitForA polls until the name resolves to want. The pull loop has its own
// interval, so the only honest assertion is "eventually, and before this
// deadline".
func waitForA(t *testing.T, server, name, want string) {
	t.Helper()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	deadline := time.After(30 * time.Second)
	for {
		// A socket that is not bound yet is a reason to wait, not to fail: only
		// the deadline decides.
		if got, err := lookupA(server, name); err == nil && slices.Contains(got, want) {
			return
		}
		select {
		case <-tick.C:
		case <-deadline:
			t.Fatalf("%s never resolved to %s on the replica", name, want)
		}
	}
}

// A snapshot must never carry a body older than the version stamped on it: a
// replica records that version and stops asking, so an old body under a new
// number is configuration it never receives. Newer is the safe direction,
// because the replica re-pulls on the next tick.
func TestSnapshotBodyIsNeverOlderThanItsVersion(t *testing.T) {
	dir := t.TempDir()
	db := openDB(t, dir)
	if err := db.PutSettings(store.Settings{PrivateDomain: "home.arpa."}); err != nil {
		t.Fatal(err)
	}
	src := &storeSource{st: db, nodeID: "primary"}

	// versionAt[k] is the config version once the k-th service existed, so a
	// body holding k services is at least as new as versionAt[k].
	var mu sync.Mutex
	versionAt := map[int]int64{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for k := 1; k <= 40; k++ {
			if _, err := db.PutService(store.Service{
				Name:      fmt.Sprintf("svc%02d", k),
				Addresses: []store.Address{{Address: "192.168.1.1"}},
			}); err != nil {
				t.Error(err)
				return
			}
			v, err := db.ConfigVersion()
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			versionAt[k] = v
			mu.Unlock()
		}
	}()

	samples := 0
	for {
		select {
		case <-done:
			if samples == 0 {
				t.Fatal("the writer finished before a single snapshot was taken")
			}
			return
		default:
		}
		snap, err := src.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		var body store.SnapshotInput
		if err := json.Unmarshal(snap.Config, &body); err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		at, known := versionAt[len(body.Services)]
		mu.Unlock()
		if !known {
			continue // the writer has not recorded that count's version yet
		}
		samples++
		if at < snap.ConfigVersion {
			t.Fatalf("snapshot stamped version %d carries %d services, which existed at version %d: the body is older than its stamp",
				snap.ConfigVersion, len(body.Services), at)
		}
	}
}

// The whole point of the replication plan: a service written on the primary is
// answered by the replica, over DNS, and keeps being answered once the primary
// is gone.
func TestEndToEndReplicaFollowsPrimary(t *testing.T) {
	primaryDir, primaryID := nodeDir(t, "primary")
	replicaDir, replicaID := nodeDir(t, "replica")

	replAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	pinPeer(t, primaryDir, store.Peer{NodeID: replicaID, Label: "replica"})
	pinPrimary(t, replicaDir, primaryID)

	primaryCfg, _, primaryAdmin := writeConfig(t, primaryDir,
		fmt.Sprintf("replication:\n  listen: %q\n", replAddr))
	replicaCfg, replicaDNS, replicaAdmin := writeConfig(t, replicaDir,
		fmt.Sprintf("replication:\n  primary: %q\n", replAddr))

	primaryCtx, stopPrimary := context.WithCancel(context.Background())
	primaryErrs := make(chan error, 1)
	go func() { primaryErrs <- Serve(primaryCtx, primaryCfg, nil) }()
	defer stopPrimary()

	replicaCtx, stopReplica := context.WithCancel(context.Background())
	defer stopReplica()
	go Serve(replicaCtx, replicaCfg, nil)

	waitForHTTP(t, fmt.Sprintf("http://127.0.0.1:%d/api/v1/healthz", primaryAdmin))
	waitForHTTP(t, fmt.Sprintf("http://127.0.0.1:%d/api/v1/healthz", replicaAdmin))

	token := waitForFile(t, filepath.Join(primaryDir, "bootstrap-token"))
	postJSON(t, fmt.Sprintf("http://127.0.0.1:%d/api/v1/services", primaryAdmin), token,
		`{"name":"kypost","addresses":[{"address":"192.168.1.20"}],"aliases":["webmail"]}`)

	replicaServer := fmt.Sprintf("127.0.0.1:%d", replicaDNS)
	waitForA(t, replicaServer, "kypost.home.arpa.", "192.168.1.20")

	// An alias is built by the zone snapshot, not stored as a name: it can only
	// answer if the pull rebuilt the snapshot rather than just writing rows.
	if got := resolveA(t, replicaServer, "webmail.home.arpa."); !slices.Contains(got, "192.168.1.20") {
		t.Errorf("alias on the replica = %v, want 192.168.1.20", got)
	}

	stopPrimary()
	select {
	case <-primaryErrs:
	case <-time.After(10 * time.Second):
		t.Fatal("the primary did not shut down within 10s")
	}

	// A replica whose primary is gone keeps serving what it last pulled. This is
	// the reason to run one at all.
	if got := resolveA(t, replicaServer, "kypost.home.arpa."); !slices.Contains(got, "192.168.1.20") {
		t.Errorf("after the primary stopped, the replica answered %v, want 192.168.1.20", got)
	}
}

// peers is "the replicas I serve" and replica_state is "the primary I follow".
// Reading the first as the second makes a node with peer rows follow one of its
// own replicas, and makes a demoted primary with three of them follow nothing.
func TestPrimaryFingerprintComesFromReplicaState(t *testing.T) {
	dir := t.TempDir()
	db := openDB(t, dir)
	if err := db.PutPeer(store.Peer{NodeID: "replica-i-serve", Label: "one"}); err != nil {
		t.Fatal(err)
	}

	if fp, err := primaryFingerprint(db); err == nil {
		t.Fatalf("primaryFingerprint = %q from a peer row; a node this node serves is not its primary", fp)
	}

	if err := db.SetReplicaState("the-primary", 0); err != nil {
		t.Fatal(err)
	}
	fp, err := primaryFingerprint(db)
	if err != nil {
		t.Fatal(err)
	}
	if fp != "the-primary" {
		t.Fatalf("primaryFingerprint = %q, want the-primary", fp)
	}
}

// A replica that was never paired has no key to authenticate its primary with.
// It must say so and carry on serving, not spin on a dial it cannot complete.
func TestUnpairedReplicaStartsAndServes(t *testing.T) {
	dir, _ := nodeDir(t, "lonely")
	cfg, dnsPort, adminPort := writeConfig(t, dir,
		fmt.Sprintf("replication:\n  primary: \"127.0.0.1:%d\"\n", freePort(t)))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logger, logged := logCapture(t)
	go Serve(ctx, cfg, logger)

	base := fmt.Sprintf("http://127.0.0.1:%d", adminPort)
	waitForHTTP(t, base+"/api/v1/healthz")
	token := waitForFile(t, filepath.Join(dir, "bootstrap-token"))
	postJSON(t, base+"/api/v1/services", token,
		`{"name":"local","addresses":[{"address":"192.168.1.30"}]}`)

	if got := resolveA(t, fmt.Sprintf("127.0.0.1:%d", dnsPort), "local.home.arpa."); !slices.Contains(got, "192.168.1.30") {
		t.Errorf("unpaired replica answered %v, want 192.168.1.30", got)
	}
	if out := logged(); !strings.Contains(out, "not paired") {
		t.Errorf("startup log does not tell the operator this node is unpaired:\n%s", out)
	}
}
