package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yoshiofthewire/kydns-server/internal/config"
	"github.com/yoshiofthewire/kydns-server/internal/replica"
)

func TestRoleFromConfig(t *testing.T) {
	cases := []struct {
		name string
		cfg  config.ReplicationConfig
		want Role
	}{
		{"standalone", config.ReplicationConfig{}, RoleStandalone},
		{"primary", config.ReplicationConfig{Listen: ":8443"}, RolePrimary},
		{"replica", config.ReplicationConfig{Primary: "10.0.0.2:8443"}, RoleReplica},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := RoleFrom(tc.cfg); got != tc.want {
				t.Fatalf("RoleFrom(%+v) = %q, want %q", tc.cfg, got, tc.want)
			}
		})
	}
}

// TestRoleHolderReportsChangedRole is the seam Task 7's Promote will use: a
// live role a later caller can flip without a restart.
func TestRoleHolderReportsChangedRole(t *testing.T) {
	h := NewRoleHolder(RoleReplica)
	if got := h.Current(); got != RoleReplica {
		t.Fatalf("Current() = %q, want %q", got, RoleReplica)
	}
	h.Set(RolePrimary)
	if got := h.Current(); got != RolePrimary {
		t.Fatalf("Current() after Set = %q, want %q", got, RolePrimary)
	}
}

// fakePullerStatus lets replicaStatus be tested without running a pull loop.
type fakePullerStatus struct{ st replica.Status }

func (f fakePullerStatus) Status() replica.Status { return f.st }

func TestReplicaStatusStandaloneHasNoPrimaryFields(t *testing.T) {
	got := replicaStatus(RoleStandalone, "", "", nil)
	if got.Role != RoleStandalone {
		t.Fatalf("Role = %q, want %q", got.Role, RoleStandalone)
	}
	if got.PrimaryAddr != "" || got.PrimaryNodeID != "" || got.LastSyncUnix != 0 || got.Stale {
		t.Fatalf("standalone status carries primary fields: %+v", got)
	}
}

// An unpaired replica has no puller, but it still knows which box its primary
// is, and the write gate's refusal has to name it. It will also never sync, so
// it says so rather than rendering like a node that is up to date.
func TestUnpairedReplicaStatusStillNamesThePrimary(t *testing.T) {
	got := replicaStatus(RoleReplica, "10.0.0.2:8443", "", nil)
	if got.PrimaryAddr != "10.0.0.2:8443" {
		t.Fatalf("PrimaryAddr = %q, want 10.0.0.2:8443", got.PrimaryAddr)
	}
	if !got.Stale || !strings.Contains(got.LastError, "not paired") {
		t.Fatalf("an unpaired replica reports stale=%v, error %q", got.Stale, got.LastError)
	}
}

// Every surface renders from this one status, and a field dropped on the way to
// one of them is how "the replica has been unlinked" becomes "check the
// network" on the screen the operator is actually looking at.
func TestLastErrorReachesBothTransports(t *testing.T) {
	const refused = `primary claims node "" but this node is pinned to fp-orchard`
	got := replicaStatus(RoleReplica, "10.0.0.2:8443", "fp-me", fakePullerStatus{st: replica.Status{
		PrimaryNodeID: "fp-orchard", LastVersion: 3, LastError: refused, Stale: true,
	}})
	if w := got.toWeb(); w.LastError != refused || !w.Stale {
		t.Errorf("the web status carries error %q, stale %v", w.LastError, w.Stale)
	}
	if a := got.toAdminAPI(); a.LastError != refused || !a.Stale {
		t.Errorf("the API status carries error %q, stale %v", a.LastError, a.Stale)
	}
}

// The config keeps naming the old primary after a promotion, so the address
// has to come from the current role, not from the file.
func TestPromotedNodeReportsNoPrimaryAddress(t *testing.T) {
	for _, role := range []Role{RolePrimary, RoleStandalone} {
		if got := replicaStatus(role, "10.0.0.2:8443", "", nil); got.PrimaryAddr != "" {
			t.Errorf("a %s reports primary_address %q", role, got.PrimaryAddr)
		}
	}
}

func TestEnvAloneMakesThisNodeAPrimary(t *testing.T) {
	t.Setenv("KYDNS_REPLICATION_LISTEN", "0.0.0.0:8443")

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "kydns.yaml")
	if err := os.WriteFile(cfgPath, []byte("data_dir: "+dir+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := RoleFrom(cfg.Replication); got != RolePrimary {
		t.Errorf("RoleFrom() = %q, want %q", got, RolePrimary)
	}
}

func TestReplicaStatusReportsPrimaryAndStaleness(t *testing.T) {
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	syncedAt := now.Add(-61 * time.Second)
	fp := fakePullerStatus{st: replica.Status{
		PrimaryNodeID: "primary-fp",
		LastSyncAt:    syncedAt,
		LastVersion:   3,
		Stale:         true,
	}}
	got := replicaStatus(RoleReplica, "10.0.0.2:8443", "this-node-fp", fp)
	if got.Role != RoleReplica {
		t.Fatalf("Role = %q, want %q", got.Role, RoleReplica)
	}
	if got.PrimaryAddr != "10.0.0.2:8443" {
		t.Fatalf("PrimaryAddr = %q, want 10.0.0.2:8443", got.PrimaryAddr)
	}
	if got.PrimaryNodeID != "primary-fp" {
		t.Fatalf("PrimaryNodeID = %q, want primary-fp", got.PrimaryNodeID)
	}
	if got.LastSyncUnix != syncedAt.Unix() {
		t.Fatalf("LastSyncUnix = %d, want %d", got.LastSyncUnix, syncedAt.Unix())
	}
	if got.LastVersion != 3 {
		t.Fatalf("LastVersion = %d, want 3", got.LastVersion)
	}
	if !got.Stale {
		t.Fatal("Stale = false, want true")
	}
	// This node's own key, not the primary's: an operator pairing a third node
	// against a replica would otherwise be handed the wrong fingerprint.
	if got.NodeID != "this-node-fp" {
		t.Fatalf("NodeID = %q, want this-node-fp", got.NodeID)
	}
}
