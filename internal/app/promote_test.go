package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yoshiofthewire/kydns-server/internal/adminapi"
	"github.com/yoshiofthewire/kydns-server/internal/registry"
	"github.com/yoshiofthewire/kydns-server/internal/replica"
)

// The fingerprint this test's puller is pinned to. It shares no substring with
// the addresses or the service names asserted below.
const pinnedPrimaryFP = "7f7f7f0011223344556677889900aabbccddeeff7f7f7f0011223344556677ab"

// recordingPrimary answers polls and counts them, so "the puller stopped" is
// asserted against requests that did not arrive rather than a flag that was
// set. Snapshot is never reached: the version it reports is the one the
// replica already holds.
type recordingPrimary struct {
	mu     sync.Mutex
	polls  int
	closes int
	polled chan struct{}
}

func (p *recordingPrimary) Version(_ context.Context, _ int64) (replica.VersionReply, error) {
	p.mu.Lock()
	p.polls++
	p.mu.Unlock()
	select {
	case p.polled <- struct{}{}:
	default:
	}
	return replica.VersionReply{SchemaVersion: replica.SchemaVersion, ConfigVersion: 0, NodeID: pinnedPrimaryFP}, nil
}

func (p *recordingPrimary) Snapshot(context.Context) (replica.Snapshot, error) {
	return replica.Snapshot{}, errors.New("the replica asked for a snapshot it already holds")
}

func (p *recordingPrimary) HealthStatus(context.Context) (map[string]string, error) {
	return map[string]string{}, nil
}

func (p *recordingPrimary) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closes++
	return nil
}

func (p *recordingPrimary) counts() (polls, closes int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.polls, p.closes
}

// waitForPolls blocks until the loop has polled n times, so the test proves the
// puller was running before it proves it stopped.
func (p *recordingPrimary) waitForPolls(t *testing.T, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		select {
		case <-p.polled:
		case <-time.After(30 * time.Second):
			t.Fatalf("the pull loop polled %d times in 30s, want at least %d", i, n)
		}
	}
}

// Promotion has to do both halves at once: stop pulling, so a primary that
// comes back cannot overwrite what this node accepts from here on, and accept
// writes immediately, with no restart in the middle of an outage.
func TestPromoteStopsPullingAndAcceptsWrites(t *testing.T) {
	const primaryAddr = "10.0.0.2:8443"
	dir := t.TempDir()
	db := openDB(t, dir)
	if err := db.SetReplicaState(pinnedPrimaryFP, 0); err != nil {
		t.Fatal(err)
	}

	prim := &recordingPrimary{polled: make(chan struct{}, 64)}
	puller := replica.NewPuller(replica.PullerConfig{
		Dial:     func(context.Context) (replica.Primary, error) { return prim, nil },
		Pinned:   pinnedPrimaryFP,
		State:    db,
		Interval: time.Millisecond,
		Ceiling:  time.Millisecond,
		Now:      time.Now,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop := runPuller(ctx, puller)

	role := NewRoleHolder(RoleReplica)
	reg := registry.New(db, "home.arpa.", func() error { return nil })
	token, err := reg.CreateToken("test")
	if err != nil {
		t.Fatal(err)
	}
	promoter := &replicaPromoter{st: db, role: role, stopPull: stop}
	api := adminapi.NewAPI(reg, nil, nil).
		WithReplication(func() adminapi.ReplicaStatus {
			return replicaStatus(role.Current(), primaryAddr, "", nil).toAdminAPI()
		}).
		WithReplicaPromoter(promoter).
		Handler()

	write := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/api/v1/views", strings.NewReader(`{"name":"lan","subnets":["10.0.0.0/24"]}`))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		api.ServeHTTP(rec, req)
		return rec
	}
	if rec := write(); rec.Code != http.StatusConflict {
		t.Fatalf("a write before promotion = %d, want 409: this node is not behaving as a replica", rec.Code)
	}
	prim.waitForPolls(t, 2)

	changed, err := promoter.Promote()
	if err != nil {
		t.Fatalf("Promote: %v", err)
	}
	if !changed {
		t.Fatal("Promote reported nothing changed on a replica")
	}
	if got := role.Current(); got != RolePrimary {
		t.Fatalf("role after promotion = %q, want %q", got, RolePrimary)
	}
	// Run defers its connection close, so a closed connection is the loop's own
	// goroutine having returned rather than a flag somebody set.
	if _, closes := prim.counts(); closes == 0 {
		t.Error("the pull loop never closed its connection, so it did not exit")
	}

	// No restart between the refusal above and this acceptance.
	if rec := write(); rec.Code != http.StatusCreated {
		t.Fatalf("a write straight after promotion = %d: %s", rec.Code, rec.Body)
	}

	// Nothing polls from here on. The loop's interval is a millisecond, so a
	// loop still running would answer this window hundreds of times over.
	for len(prim.polled) > 0 {
		<-prim.polled // polls already in flight when the stop was asked for
	}
	select {
	case <-prim.polled:
		t.Error("the primary was polled after promotion; the pull loop is still running")
	case <-time.After(250 * time.Millisecond):
	}

	// The primary it was following is cleared, and the promotion is recorded
	// where a restart will find it.
	if fp, _, err := db.ReplicaState(); err != nil || fp != "" {
		t.Errorf("replica_state names %q after promotion (err %v), want it cleared", fp, err)
	}
	if at, err := db.Promotion(); err != nil || at == 0 {
		t.Errorf("Promotion() = %d, %v, want a recorded promotion", at, err)
	}
}

// Promotion is recorded in the database, so replication.primary is still in
// the config file afterwards. The recorded promotion has to win, or the node
// goes back to being overwritten by the primary the operator promoted away
// from.
func TestPromoteSurvivesRestart(t *testing.T) {
	dir, _ := nodeDir(t, "promoted")
	primaryAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	cfgPath, _, adminPort := writeConfig(t, dir, fmt.Sprintf("replication:\n  primary: %q\n", primaryAddr))
	base := fmt.Sprintf("http://127.0.0.1:%d", adminPort)
	// Paired, so the first run really does start a pull loop for the promotion
	// to stop. Nothing is listening on that address; the loop backs off.
	pinPrimary(t, dir, pinnedPrimaryFP)

	run := func() (stop func(), logged func() string) {
		ctx, cancel := context.WithCancel(context.Background())
		logger, logged := logCapture(t)
		done := make(chan error, 1)
		go func() { done <- Serve(ctx, cfgPath, logger) }()
		waitForHTTP(t, base+"/api/v1/healthz")
		return func() {
			cancel()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("the daemon did not shut down within 10s")
			}
		}, logged
	}

	stop, _ := run()
	token := waitForFile(t, filepath.Join(dir, "bootstrap-token"))
	const beforeSvc = `{"name":"attic","addresses":[{"address":"192.168.1.41"}]}`
	if code, body := postStatus(t, base+"/api/v1/services", token, beforeSvc); code != http.StatusConflict {
		t.Fatalf("a write on the unpromoted node = %d: %s", code, body)
	}

	var reply struct {
		Role     string `json:"role"`
		Promoted bool   `json:"promoted"`
	}
	if code := apiJSON(t, "POST", base+adminapi.PathReplicaPromote, token, &reply); code != http.StatusOK {
		t.Fatalf("POST %s = %d", adminapi.PathReplicaPromote, code)
	}
	if !reply.Promoted {
		t.Fatalf("promote reply = %+v, want a node that changed role", reply)
	}
	if code, body := postStatus(t, base+"/api/v1/services", token, beforeSvc); code != http.StatusCreated {
		t.Fatalf("a write straight after promotion = %d: %s", code, body)
	}
	stop()

	// The operator's config file is not something KyDNS edits: it still names
	// the primary this node used to follow, and the promotion still wins.
	cfgBody, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(cfgBody), primaryAddr) {
		t.Fatalf("replication.primary was rewritten out of the operator's config file:\n%s", cfgBody)
	}

	stop, logged := run()
	defer stop()
	// A promoted node does not go near the replica branch at startup: it neither
	// follows the primary still named in the file nor complains about not being
	// paired with it.
	for _, unwanted := range []string{"following primary", "not paired"} {
		if strings.Contains(logged(), unwanted) {
			t.Errorf("the restarted node logged %q; it is still treating itself as a replica:\n%s",
				unwanted, logged())
		}
	}
	var status struct {
		Role string `json:"role"`
	}
	if code := apiJSON(t, "GET", base+"/api/v1/replica/status", token, &status); code != http.StatusOK {
		t.Fatalf("GET /replica/status = %d", code)
	}
	if status.Role != string(RolePrimary) {
		t.Fatalf("role after restart = %q, want %q: the recorded promotion lost to the config file",
			status.Role, RolePrimary)
	}
	const afterSvc = `{"name":"shed","addresses":[{"address":"192.168.1.42"}]}`
	if code, body := postStatus(t, base+"/api/v1/services", token, afterSvc); code != http.StatusCreated {
		t.Fatalf("a write after the restart = %d: %s", code, body)
	}
}

// Promoting a node that is already a primary writes nothing and stops nothing:
// the operator asked for a state it is in, and a recorded promotion here would
// outlive a later demotion.
func TestPromotingAPrimaryChangesNothing(t *testing.T) {
	db := openDB(t, t.TempDir())
	stopped := false
	p := &replicaPromoter{st: db, role: NewRoleHolder(RolePrimary), stopPull: func() { stopped = true }}

	changed, err := p.Promote()
	if err != nil {
		t.Fatalf("Promote on a primary: %v", err)
	}
	if changed {
		t.Error("Promote reported a change on a node that was already a primary")
	}
	if stopped {
		t.Error("Promote stopped a pull loop on a primary")
	}
	if at, err := db.Promotion(); err != nil || at != 0 {
		t.Errorf("Promotion() = %d, %v, want nothing recorded", at, err)
	}
}

// Joining is the demotion, so it has to take the promotion off this node.
// A former primary that re-pairs and then comes back a primary on the next
// restart is the two-primaries state this design cannot reconcile.
func TestJoinClearsARecordedPromotion(t *testing.T) {
	primaryDir, _ := nodeDir(t, "primary")
	joinerDir, _ := nodeDir(t, "joiner")
	admin, primaryID, addr := startPrimaryListener(t, primaryDir)
	j := newJoiner(t, joinerDir)

	if err := j.st.RecordPromotion(time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	code, _, err := admin.Invite()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.Join(joinCtx(t), addr, code, primaryID.NodeID); err != nil {
		t.Fatalf("Join: %v", err)
	}
	if at, err := j.st.Promotion(); err != nil || at != 0 {
		t.Fatalf("Promotion() = %d, %v after joining a primary, want it cleared", at, err)
	}
}
