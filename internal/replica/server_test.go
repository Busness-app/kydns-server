package replica

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yoshiofthewire/kydns-server/internal/store"
)

func newIdentity(t *testing.T) *Identity {
	t.Helper()
	id, err := LoadOrCreateIdentity(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// fakePeers is the pinned set, mutable so a test can unpair mid-connection.
type fakePeers struct {
	mu       sync.Mutex
	pinned   map[string]store.Peer
	touched  []string
	versions []*int64
}

func newFakePeers(ids ...string) *fakePeers {
	f := &fakePeers{pinned: map[string]store.Peer{}}
	for _, id := range ids {
		f.pinned[id] = store.Peer{NodeID: id}
	}
	return f
}

func (f *fakePeers) Peer(nodeID string) (store.Peer, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.pinned[nodeID]
	if !ok {
		return store.Peer{}, fmt.Errorf("%w: peer %s", store.ErrNotFound, nodeID)
	}
	return p, nil
}

func (f *fakePeers) Peers() ([]store.Peer, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []store.Peer{}
	for _, p := range f.pinned {
		out = append(out, p)
	}
	return out, nil
}

func (f *fakePeers) PutPeer(p store.Peer) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pinned[p.NodeID] = p
	return nil
}

func (f *fakePeers) TouchPeer(nodeID string, syncedAt int64, version *int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.touched = append(f.touched, nodeID)
	f.versions = append(f.versions, version)
	return nil
}

func (f *fakePeers) reportedVersions() []*int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*int64(nil), f.versions...)
}

// shown renders the recorded versions readably: a failure about pointers helps
// nobody.
func shown(vs []*int64) string {
	out := make([]string, len(vs))
	for i, v := range vs {
		if v == nil {
			out[i] = "none"
			continue
		}
		out[i] = fmt.Sprint(*v)
	}
	return strings.Join(out, ",")
}

func (f *fakePeers) touches() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.touched)
}

// fakeSource bumps its version on every read, so a server that reads the
// version and the body in separate calls ships a mismatched pair.
type fakeSource struct {
	mu      sync.Mutex
	version int64
	health  map[string]string
	nodeID  string
}

func (f *fakeSource) next() int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.version++
	return f.version
}

// id defaults to "primary": most tests here never check it against a pin.
func (f *fakeSource) id() string {
	if f.nodeID == "" {
		return "primary"
	}
	return f.nodeID
}

func (f *fakeSource) Version() (VersionReply, error) {
	return VersionReply{SchemaVersion: SchemaVersion, ConfigVersion: f.next(), NodeID: f.id()}, nil
}

func (f *fakeSource) HealthStatus() (map[string]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.health, nil
}

func (f *fakeSource) Snapshot() (Snapshot, error) {
	v := f.next()
	return Snapshot{
		SchemaVersion: SchemaVersion,
		ConfigVersion: v,
		NodeID:        "primary",
		Config:        json.RawMessage(fmt.Sprintf(`{"n":%d}`, v)),
	}, nil
}

func startServer(t *testing.T, peers PeerStore, src Source) (srv *Server, addr, primaryFP string) {
	t.Helper()
	id := newIdentity(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv = NewServer(id, peers, src, NewInviteBook(time.Minute, time.Now))
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return srv, l.Addr().String(), id.NodeID
}

// rawDo speaks to the server without the client wrapper, so a test can assert
// on the status code rather than on an error string.
func rawDo(t *testing.T, addr string, id *Identity, want, method, path string) *http.Response {
	t.Helper()
	cfg, err := pinnedTLSConfig(id, func(fp string) bool { return fp == want })
	if err != nil {
		t.Fatal(err)
	}
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: 10 * time.Second}
	defer c.CloseIdleConnections()
	req, err := http.NewRequest(method, "https://"+addr+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// An unpinned peer is a stranger. It gets a refusal, not a snapshot.
func TestServerRefusesUnpinnedPeer(t *testing.T) {
	peers := newFakePeers()
	_, addr, fp := startServer(t, peers, &fakeSource{})

	for _, path := range []string{"/replica/version", "/replica/snapshot"} {
		resp := rawDo(t, addr, newIdentity(t), fp, http.MethodGet, path)
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("GET %s status = %d, want %d", path, resp.StatusCode, http.StatusForbidden)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(body), "config_version") {
			t.Errorf("refused peer still received a reply from %s: %s", path, body)
		}
	}
	if peers.touches() != 0 {
		t.Fatalf("TouchPeer called %d times for an unpinned peer, want 0", peers.touches())
	}
}

// Authorization runs before routing, so a stranger cannot map the surface by
// reading 405 for a route that exists and 404 for one that does not.
func TestUnpinnedPeerLearnsNothingAboutRoutes(t *testing.T) {
	_, addr, fp := startServer(t, newFakePeers(), &fakeSource{})
	stranger := newIdentity(t)

	for _, c := range []struct{ method, path string }{
		{http.MethodPost, "/replica/version"},
		{http.MethodGet, "/replica/nonexistent"},
	} {
		resp := rawDo(t, addr, stranger, fp, c.method, c.path)
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s %s status = %d, want %d for every request from a stranger",
				c.method, c.path, resp.StatusCode, http.StatusForbidden)
		}
	}
}

// Pinning is the default, not something a route opts into. A handler added
// later without a thought must still be closed to strangers.
func TestRouteAddedWithoutThoughtIsStillPinned(t *testing.T) {
	client := newIdentity(t)
	srv, addr, fp := startServer(t, newFakePeers(client.NodeID), &fakeSource{})
	srv.mux.HandleFunc("GET /replica/forgotten", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("secrets"))
	})

	if resp := rawDo(t, addr, newIdentity(t), fp, http.MethodGet, "/replica/forgotten"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unpinned peer reached a route nobody wrapped: status %d, want %d",
			resp.StatusCode, http.StatusForbidden)
	}
	if resp := rawDo(t, addr, client, fp, http.MethodGet, "/replica/forgotten"); resp.StatusCode != http.StatusOK {
		t.Fatalf("pinned peer status = %d on the same route, want %d", resp.StatusCode, http.StatusOK)
	}
}

// Pairing is the one exemption, and it has to work: a peer becomes pinned by
// reaching it while unpinned.
func TestExemptRouteIsReachableUnpinned(t *testing.T) {
	srv, addr, fp := startServer(t, newFakePeers(), &fakeSource{})
	srv.mux.HandleFunc("GET /replica/pair", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello"))
	})

	if resp := rawDo(t, addr, newIdentity(t), fp, http.MethodGet, "/replica/pair"); resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /replica/pair status = %d for an unpinned peer, want %d; pairing is unreachable",
			resp.StatusCode, http.StatusOK)
	}
}

// Every stage of a connection needs a deadline, or a peer that completes a
// handshake and then stalls costs a goroutine indefinitely. Timing these out
// for real would mean sleeping, so the configuration is what is checked.
func TestServerBoundsEveryStageOfAConnection(t *testing.T) {
	srv, _, _ := startServer(t, newFakePeers(), &fakeSource{})
	for name, d := range map[string]time.Duration{
		"ReadHeaderTimeout": srv.http.ReadHeaderTimeout,
		"WriteTimeout":      srv.http.WriteTimeout,
		"IdleTimeout":       srv.http.IdleTimeout,
	} {
		if d <= 0 {
			t.Errorf("%s = %v, want a deadline", name, d)
		}
	}
}

func TestPinnedPeerReadsVersionAndSnapshot(t *testing.T) {
	client := newIdentity(t)
	peers := newFakePeers(client.NodeID)
	_, addr, fp := startServer(t, peers, &fakeSource{})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := NewClient(addr, client, fp)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	v, err := c.Version(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if v.SchemaVersion != SchemaVersion || v.ConfigVersion == 0 {
		t.Fatalf("Version() = %+v, want schema %d and a non-zero config version", v, SchemaVersion)
	}

	s, err := c.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if s.SchemaVersion != SchemaVersion || len(s.Config) == 0 {
		t.Fatalf("Snapshot() = %+v, want schema %d and a config body", s, SchemaVersion)
	}
	if peers.touches() != 2 {
		t.Fatalf("TouchPeer called %d times, want one per served request (2)", peers.touches())
	}
}

// Version lag is the replica's number, not the primary's. Recording what the
// primary just read out of its own store would make every replica look current
// however far behind it really is.
func TestPeerVersionIsWhatTheReplicaReports(t *testing.T) {
	client := newIdentity(t)
	peers := newFakePeers(client.NodeID)
	src := &fakeSource{version: 40} // the primary is at 41 by the time it answers
	_, addr, fp := startServer(t, peers, src)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := NewClient(addr, client, fp)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if _, err := c.Version(ctx, 7); err != nil {
		t.Fatal(err)
	}
	got := peers.reportedVersions()
	if len(got) != 1 || got[0] == nil || *got[0] != 7 {
		t.Fatalf("recorded peer version %v, want the 7 the replica reported holding", shown(got))
	}

	// A replica that reports nothing still updates its last-seen time, and does
	// not have its recorded version overwritten with the primary's.
	if resp := rawDo(t, addr, client, fp, http.MethodGet, "/replica/version"); resp.StatusCode != http.StatusOK {
		t.Fatalf("GET without a version = %d, want 200", resp.StatusCode)
	}
	got = peers.reportedVersions()
	if len(got) != 2 || got[1] != nil {
		t.Fatalf("a replica reporting nothing recorded %v, want no version at all", shown(got))
	}
}

// Unpairing has to bite on the live connection, not only on the next process.
func TestRemovedPeerIsRefusedOnNextRequest(t *testing.T) {
	client := newIdentity(t)
	db, err := store.Open(filepath.Join(t.TempDir(), "kydns.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.PutPeer(store.Peer{NodeID: client.NodeID, Label: "replica"}); err != nil {
		t.Fatal(err)
	}
	_, addr, fp := startServer(t, db, &fakeSource{})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := NewClient(addr, client, fp)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if _, err := c.Version(ctx, 0); err != nil {
		t.Fatalf("Version() before unpairing: %v", err)
	}
	if err := db.DeletePeer(client.NodeID); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Version(ctx, 0); err == nil {
		t.Fatal("Version() succeeded after the peer was deleted; the pin is checked once, not per request")
	}
}

// Replication is read-only. A write method must not be a way in.
func TestServerRejectsNonGETMethods(t *testing.T) {
	client := newIdentity(t)
	_, addr, fp := startServer(t, newFakePeers(client.NodeID), &fakeSource{})

	for _, path := range []string{"/replica/version", "/replica/snapshot"} {
		for _, method := range []string{http.MethodPost, http.MethodDelete, http.MethodPut} {
			resp := rawDo(t, addr, client, fp, method, path)
			if resp.StatusCode != http.StatusMethodNotAllowed {
				t.Errorf("%s %s status = %d, want %d", method, path, resp.StatusCode, http.StatusMethodNotAllowed)
			}
		}
	}
}

// A version reply must never describe a different configuration than the
// snapshot shipped with it.
func TestSnapshotVersionMatchesItsBody(t *testing.T) {
	client := newIdentity(t)
	_, addr, fp := startServer(t, newFakePeers(client.NodeID), &fakeSource{})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := NewClient(addr, client, fp)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	for i := 0; i < 3; i++ {
		s, err := c.Snapshot(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var body struct {
			N int64 `json:"n"`
		}
		if err := json.Unmarshal(s.Config, &body); err != nil {
			t.Fatalf("config %s: %v", s.Config, err)
		}
		if body.N != s.ConfigVersion {
			t.Fatalf("snapshot reports version %d but carries the config read at %d", s.ConfigVersion, body.N)
		}
	}
}

// The server must ask for a client certificate: the peer's key is the only
// credential in this design.
func TestServerRequiresAClientCertificate(t *testing.T) {
	_, addr, fp := startServer(t, newFakePeers(), &fakeSource{})

	cfg, err := pinnedTLSConfig(newIdentity(t), func(got string) bool { return got == fp })
	if err != nil {
		t.Fatal(err)
	}
	cfg.Certificates = nil // present no client certificate at all

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
	defer client.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+addr+"/replica/version", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err == nil {
		resp.Body.Close()
		t.Fatalf("server answered %d with no client certificate presented", resp.StatusCode)
	}
}
