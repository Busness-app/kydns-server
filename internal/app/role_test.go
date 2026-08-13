package app

import (
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
	got := replicaStatus(RoleStandalone, "", nil)
	if got.Role != RoleStandalone {
		t.Fatalf("Role = %q, want %q", got.Role, RoleStandalone)
	}
	if got.PrimaryAddr != "" || got.PrimaryNodeID != "" || got.LastSyncUnix != 0 || got.Stale {
		t.Fatalf("standalone status carries primary fields: %+v", got)
	}
}

// An unpaired replica has no puller, but it still knows which box its primary
// is, and the write gate's refusal has to name it.
func TestUnpairedReplicaStatusStillNamesThePrimary(t *testing.T) {
	if got := replicaStatus(RoleReplica, "10.0.0.2:8443", nil); got.PrimaryAddr != "10.0.0.2:8443" {
		t.Fatalf("PrimaryAddr = %q, want 10.0.0.2:8443", got.PrimaryAddr)
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
	got := replicaStatus(RoleReplica, "10.0.0.2:8443", fp)
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
}
