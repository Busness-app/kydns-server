package replica

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

// TestHealthStatusReplicates is the ordinary path: a service unhealthy on the
// primary reads unhealthy on the replica after one poll.
func TestHealthStatusReplicates(t *testing.T) {
	client := newIdentity(t)
	peers := newFakePeers(client.NodeID)
	src := &fakeSource{health: map[string]string{"web": "unhealthy", "dns": "healthy"}}
	_, addr, fp := startServer(t, peers, src)

	c, err := NewClient(addr, client, fp)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	got, err := c.HealthStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got["web"] != "unhealthy" || got["dns"] != "healthy" {
		t.Fatalf("HealthStatus() = %+v, want web=unhealthy dns=healthy", got)
	}

	src.nodeID = fp // the puller checks the reply names the pin it dialled
	st := &fakeState{nodeID: fp, version: 0}
	p := NewPuller(PullerConfig{
		Dial:     func(context.Context) (Primary, error) { return NewClient(addr, client, fp) },
		Pinned:   fp,
		Apply:    &fakeApplier{},
		State:    st,
		Interval: 5 * time.Second,
		Ceiling:  60 * time.Second,
		Now:      (&clock{t: time.Unix(1000, 0)}).now,
	})
	p.poll(context.Background())

	if got := p.Health(); got["web"] != "unhealthy" {
		t.Fatalf("Puller.Health() = %+v, want web=unhealthy", got)
	}
}

// TestUnreachablePrimaryReportsHealthUnknownNotStale is the behaviour that
// matters: a replica that already holds a good health value must drop it to
// unknown the moment its primary stops answering, not keep serving it.
func TestUnreachablePrimaryReportsHealthUnknownNotStale(t *testing.T) {
	prim := &fakePrimary{version: 1, healthStatuses: map[string]string{"web": "unhealthy"}}
	c := &clock{t: time.Unix(1000, 0)}
	p := newTestPuller(prim, &fakeApplier{}, &fakeState{nodeID: pinnedFP, version: 1}, c.now)

	// Establish a known-good value first.
	p.poll(context.Background())
	if got := p.Health(); got["web"] != "unhealthy" {
		t.Fatalf("Health() after a good poll = %+v, want web=unhealthy", got)
	}

	// The primary goes dark.
	prim.versionErr = errors.New("connection refused")
	c.add(5 * time.Second)
	p.poll(context.Background())

	got := p.Health()
	if got["web"] != "unknown" {
		t.Fatalf("Health() with the primary unreachable = %+v, want web=unknown, not the stale unhealthy value", got)
	}
}

// TestHealthDoesNotAffectConfigVersion: health rides its own request, so a
// health flap must never look like a configuration change and wake a
// snapshot pull.
func TestHealthDoesNotAffectConfigVersion(t *testing.T) {
	prim := &fakePrimary{version: 7, healthStatuses: map[string]string{"web": "healthy"}}
	st := &fakeState{nodeID: pinnedFP, version: 7}
	c := &clock{t: time.Unix(1000, 0)}
	p := newTestPuller(prim, &fakeApplier{}, st, c.now)

	p.poll(context.Background())
	if prim.snapshotCalls != 0 {
		t.Fatalf("snapshot fetches = %d after health matched an unchanged config version, want 0", prim.snapshotCalls)
	}

	// Health flips on the primary; the config version does not move.
	prim.healthStatuses = map[string]string{"web": "unhealthy"}
	c.add(5 * time.Second)
	p.poll(context.Background())

	if prim.snapshotCalls != 0 {
		t.Fatalf("snapshot fetches = %d after a health flap, want 0: health must not move config_version", prim.snapshotCalls)
	}
	if got := p.Status().LastVersion; got != 7 {
		t.Fatalf("LastVersion = %d after a health flap, want the unchanged 7", got)
	}
	if got := p.Health(); got["web"] != "unhealthy" {
		t.Fatalf("Health() = %+v, want the flap to have landed", got)
	}
}

// TestWrongKeyPeerBacksOff is the carried fix from part 1: reachable() used to
// fire before the node ID check, so a peer answering with the wrong key held
// the loop at the plain 5s interval forever instead of backing off.
func TestWrongKeyPeerBacksOff(t *testing.T) {
	prim := &fakePrimary{version: 3, nodeID: "attacker-fp"}
	p := newTestPuller(prim, &fakeApplier{}, &fakeState{}, (&clock{t: time.Unix(1000, 0)}).now)

	p.poll(context.Background())

	if got := p.wait(); got <= 5*time.Second {
		t.Fatalf("wait after a wrong-key reply = %v, want more than the 5s interval", got)
	}
}

// A pinned route stays pinned: health must not become the exception that lets
// an unpaired peer learn anything about the primary.
func TestHealthStatusNotServedToUnpinnedPeer(t *testing.T) {
	_, addr, fp := startServer(t, newFakePeers(), &fakeSource{health: map[string]string{"web": "healthy"}})

	resp := rawDo(t, addr, newIdentity(t), fp, http.MethodGet, "/replica/health-status")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("GET /replica/health-status status = %d for an unpinned peer, want %d", resp.StatusCode, http.StatusForbidden)
	}
}
