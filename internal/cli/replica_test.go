package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The operator reads the fingerprint off this screen and confirms it on the
// replica before typing the code. A code with no fingerprint beside it invites
// them to skip that check, which is the whole attack this design closes.
func TestReplicaInvitePrintsCodeAndFingerprint(t *testing.T) {
	const (
		code = "K7QP2M9XTV4RB3ZC"
		fp   = "aa11bb22cc33dd44ee55ff6600778899aa11bb22cc33dd44ee55ff6600778899"
	)
	expires := time.Now().Add(10 * time.Minute).Unix()
	var gotMethod, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		json.NewEncoder(w).Encode(map[string]any{
			"code": code, "node_id": fp, "expires_at": expires,
		})
	}))
	defer srv.Close()

	c := &Client{BaseURL: srv.URL, Token: "t", HTTP: srv.Client()}
	var out, errOut bytes.Buffer
	if rc := replicaCmd(c, []string{"invite"}, &out, &errOut); rc != 0 {
		t.Fatalf("exit = %d, stderr = %s", rc, errOut.String())
	}
	if gotMethod != "POST" || gotPath != "/api/v1/replicas/invite" {
		t.Errorf("sent %s %s, want POST /api/v1/replicas/invite", gotMethod, gotPath)
	}
	printed := out.String()
	if !strings.Contains(printed, code) {
		t.Errorf("the pairing code is not printed:\n%s", printed)
	}
	if !strings.Contains(printed, fp) {
		t.Errorf("this node's fingerprint is not printed beside the code:\n%s", printed)
	}
	// Both belong to one operation; a screen that separates them is one the
	// operator can mis-read across two invites.
	if !strings.Contains(printed, "fingerprint") {
		t.Errorf("the fingerprint is printed but not labelled:\n%s", printed)
	}
	if !strings.Contains(printed, time.Unix(expires, 0).Format(time.RFC3339)) {
		t.Errorf("the expiry is not printed:\n%s", printed)
	}
}

func TestReplicaListRendersLagAndLastSync(t *testing.T) {
	synced := time.Unix(1755000000, 0)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"config_version": 42,
			"replicas": []map[string]any{
				{"node_id": "fp-attic", "label": "attic", "last_sync_at": synced.Unix(),
					"last_version": 40, "lag": 2, "status": "behind"},
				{"node_id": "fp-shed", "label": "shed", "last_sync_at": 0,
					"last_version": 0, "lag": 42, "status": "never_synced"},
			},
		})
	}))
	defer srv.Close()

	c := &Client{BaseURL: srv.URL, Token: "t", HTTP: srv.Client()}
	var out, errOut bytes.Buffer
	if rc := replicaCmd(c, []string{"list"}, &out, &errOut); rc != 0 {
		t.Fatalf("exit = %d, stderr = %s", rc, errOut.String())
	}
	var attic, shed string
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if strings.Contains(line, "fp-attic") {
			attic = line
		}
		if strings.Contains(line, "fp-shed") {
			shed = line
		}
	}
	if attic == "" || shed == "" {
		t.Fatalf("both replicas must be listed:\n%s", out.String())
	}
	for _, want := range []string{"attic", "behind", "lag 2", "last sync " + synced.Format(time.RFC3339)} {
		if !strings.Contains(attic, want) {
			t.Errorf("the behind row is missing %q:\n%s", want, attic)
		}
	}
	// A replica that has never synced must not read as "synced at the epoch".
	// Matched with its label, because the status word already says "never".
	if !strings.Contains(shed, "last sync never") {
		t.Errorf("a replica that never synced does not say so:\n%s", shed)
	}
	for _, epoch := range []string{"1969", "1970"} {
		if strings.Contains(shed, epoch) {
			t.Errorf("a zero last-sync rendered as a date:\n%s", shed)
		}
	}
}

func TestReplicaRemoveSendsDelete(t *testing.T) {
	var gotMethod, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := &Client{BaseURL: srv.URL, Token: "t", HTTP: srv.Client()}
	var out, errOut bytes.Buffer
	if rc := replicaCmd(c, []string{"remove", "fp-attic"}, &out, &errOut); rc != 0 {
		t.Fatalf("exit = %d, stderr = %s", rc, errOut.String())
	}
	if gotMethod != "DELETE" || gotPath != "/api/v1/replicas/fp-attic" {
		t.Errorf("sent %s %s, want DELETE /api/v1/replicas/fp-attic", gotMethod, gotPath)
	}
	if !strings.Contains(out.String(), "fp-attic") {
		t.Errorf("removal is not confirmed by name:\n%s", out.String())
	}
}

// A replica refuses these two, and the reason has to reach the operator rather
// than a bare exit code.
func TestReplicaWriteRefusalIsReported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{
			"code": "read_only_replica", "message": "this node is a read-only replica; make this change on 10.0.0.2:8443",
		}})
	}))
	defer srv.Close()

	c := &Client{BaseURL: srv.URL, Token: "t", HTTP: srv.Client()}
	var out, errOut bytes.Buffer
	if rc := replicaCmd(c, []string{"invite"}, &out, &errOut); rc != 1 {
		t.Fatalf("exit = %d, want 1", rc)
	}
	if !strings.Contains(errOut.String(), "10.0.0.2:8443") {
		t.Errorf("the refusal does not name the primary:\n%s", errOut.String())
	}
	// A refused invite must not print a half-formed pairing screen.
	if out.Len() != 0 {
		t.Errorf("a refused invite still printed to stdout:\n%s", out.String())
	}
}

func TestReplicaUsage(t *testing.T) {
	c := &Client{BaseURL: "http://127.0.0.1:1", Token: "t", HTTP: http.DefaultClient}
	for _, args := range [][]string{{}, {"wat"}, {"remove"}} {
		var out, errOut bytes.Buffer
		if rc := replicaCmd(c, args, &out, &errOut); rc != 2 {
			t.Errorf("replica %v exit = %d, want 2", args, rc)
		}
	}
}

// The dispatcher has to know the subcommand, or none of the above is reachable.
func TestRunDispatchesReplica(t *testing.T) {
	var out, errOut bytes.Buffer
	if rc := Run([]string{"replica"}, &out, &errOut); rc != 2 {
		t.Fatalf("kydns replica exit = %d, want 2", rc)
	}
	if strings.Contains(errOut.String(), "unknown subcommand") {
		t.Errorf("replica is not dispatched:\n%s", errOut.String())
	}
}
