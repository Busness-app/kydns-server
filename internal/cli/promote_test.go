package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The counts the demotion summary must report. They differ from each other and
// from every port and digit in the fixture addresses, so a summary that swapped
// them fails.
const (
	demoteServices = 3
	demoteRecords  = 7
	// The warning promotion must carry. A phrase, not a word: the surrounding
	// text says "primary" several times over.
	promoteWarning = "demoted or rebuilt"
)

// nodeRecorder is the daemon the CLI talks to for promotion and demotion. It
// records the two calls that change anything, so a declined confirmation is
// asserted against requests that never arrived.
type nodeRecorder struct {
	role      string
	promotes  int
	joins     int
	statusGet int
}

func startNodeServer(t *testing.T, role string) (*Client, *nodeRecorder) {
	t.Helper()
	rec := &nodeRecorder{role: role}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/replica/promote":
			rec.promotes++
			promoted := rec.role == "replica"
			if promoted {
				rec.role = "primary"
			}
			json.NewEncoder(w).Encode(map[string]any{"role": rec.role, "promoted": promoted})
		case "/api/v1/replica/status":
			rec.statusGet++
			json.NewEncoder(w).Encode(map[string]any{"role": rec.role, "primary_address": "10.0.0.9:8443"})
		case "/api/v1/services":
			svcs := make([]map[string]any, demoteServices)
			for i := range svcs {
				svcs[i] = map[string]any{"name": "svc"}
			}
			json.NewEncoder(w).Encode(map[string]any{"services": svcs})
		case "/api/v1/records":
			recs := make([]map[string]any, demoteRecords)
			for i := range recs {
				recs[i] = map[string]any{"name": "rec", "type": "A", "value": "192.168.1.60"}
			}
			json.NewEncoder(w).Encode(map[string]any{"records": recs})
		case "/api/v1/replica/pair/peek":
			json.NewEncoder(w).Encode(map[string]string{"fingerprint": presentedFP})
		case "/api/v1/replica/join":
			rec.joins++
			json.NewEncoder(w).Encode(map[string]string{"primary_node_id": presentedFP})
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return &Client{BaseURL: srv.URL, Token: "t", HTTP: srv.Client()}, rec
}

// labelled finds the "<label>  <value>" line the summary prints, so a count is
// matched against its own label rather than against the whole screen.
func labelled(out, label string) string {
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == label {
			return strings.Join(f[1:], " ")
		}
	}
	return ""
}

// Two primaries serving the same replicas is the one state this design cannot
// detect, so the operator is told what has to happen to the old one before
// anything is promoted.
func TestPromoteWarnsAboutTheOldPrimaryBeforeAsking(t *testing.T) {
	c, rec := startNodeServer(t, "replica")
	var out, errOut bytes.Buffer

	if rc := replicaPromote(c, nil, strings.NewReader("yes\n"), true, &out, &errOut); rc != 0 {
		t.Fatalf("exit = %d, stderr = %s", rc, errOut.String())
	}
	warned, asked := strings.Index(out.String(), promoteWarning), strings.Index(out.String(), "[yes/no]")
	if warned < 0 || asked < 0 || warned > asked {
		t.Fatalf("the old primary warning was not shown before the question:\n%s", out.String())
	}
	if rec.promotes != 1 {
		t.Fatalf("the node was promoted %d times, want 1", rec.promotes)
	}
}

func TestPromoteDeclinedChangesNothing(t *testing.T) {
	for _, answer := range []string{"no\n", ""} {
		c, rec := startNodeServer(t, "replica")
		var out, errOut bytes.Buffer
		if rc := replicaPromote(c, nil, strings.NewReader(answer), true, &out, &errOut); rc == 0 {
			t.Errorf("answer %q: a declined promotion exited 0", answer)
		}
		if rec.promotes != 0 {
			t.Errorf("answer %q: the node was promoted %d times after declining", answer, rec.promotes)
		}
	}
}

// A node that changed nothing is told which role it actually has. Re-running
// the command after a timeout must not read like a failure, and a standalone
// node must never be told it is a primary: it would send the operator looking
// for replicas that do not exist.
func TestPromoteThatChangesNothingNamesTheRealRole(t *testing.T) {
	for _, role := range []string{"primary", "standalone"} {
		c, _ := startNodeServer(t, role)
		var out, errOut bytes.Buffer
		if rc := replicaPromote(c, []string{"--yes"}, refusingReader{t}, false, &out, &errOut); rc != 0 {
			t.Fatalf("%s: exit = %d, stderr = %s", role, rc, errOut.String())
		}
		if !strings.Contains(out.String(), "nothing changed: this node is a "+role) {
			t.Errorf("a %s is not told what it is:\n%s", role, out.String())
		}
		if role == "standalone" && strings.Contains(out.String(), "primary") {
			t.Errorf("a standalone node is told it is a primary:\n%s", out.String())
		}
	}
}

// Promotion opens no listener: that key is replication.listen, and a promoted
// replica's config does not have one. An operator who repoints replicas first
// gets refused connections and nothing anywhere to read about why.
func TestPromoteSaysReplicasCannotFollowYet(t *testing.T) {
	c, _ := startNodeServer(t, "replica")
	var out, errOut bytes.Buffer
	if rc := replicaPromote(c, []string{"--yes"}, refusingReader{t}, false, &out, &errOut); rc != 0 {
		t.Fatalf("exit = %d, stderr = %s", rc, errOut.String())
	}
	for _, want := range []string{"Replicas cannot follow it yet", "replication.listen", "restart"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the success message does not mention %q:\n%s", want, out.String())
		}
	}
}

// Joining a primary discards everything this node serves. The summary names
// what goes, so nobody discovers the loss on the first pull.
func TestDemoteNamesWhatItWillDiscard(t *testing.T) {
	c, rec := startNodeServer(t, "primary")
	var out, errOut bytes.Buffer

	args := []string{joinAddress, joinCode, fingerprintF, presentedFP}
	if rc := replicaJoin(c, args, strings.NewReader("yes\n"), true, &out, &errOut); rc != 0 {
		t.Fatalf("exit = %d, stderr = %s", rc, errOut.String())
	}
	if got := labelled(out.String(), "services"); got != "3" {
		t.Errorf("the summary reports %q services, want 3:\n%s", got, out.String())
	}
	if got := labelled(out.String(), "records"); got != "7" {
		t.Errorf("the summary reports %q records, want 7:\n%s", got, out.String())
	}
	if !strings.Contains(out.String(), joinAddress) {
		t.Errorf("the summary does not name the primary this node will follow:\n%s", out.String())
	}
	if rec.joins != 1 {
		t.Fatalf("the confirmed join sent %d pairings, want 1", rec.joins)
	}
}

// Declining pairs nothing at all: the node keeps its configuration and its
// role, and the primary never hears from it.
func TestDemoteRequiresConfirmation(t *testing.T) {
	for _, answer := range []string{"no\n", ""} {
		c, rec := startNodeServer(t, "primary")
		var out, errOut bytes.Buffer
		args := []string{joinAddress, joinCode, fingerprintF, presentedFP}
		if rc := replicaJoin(c, args, strings.NewReader(answer), true, &out, &errOut); rc == 0 {
			t.Errorf("answer %q: a declined demotion exited 0", answer)
		}
		if rec.joins != 0 {
			t.Errorf("answer %q: %d pairings were sent after declining", answer, rec.joins)
		}
	}
	// No terminal and no --yes is not consent either: there is nowhere to ask.
	c, rec := startNodeServer(t, "primary")
	var out, errOut bytes.Buffer
	args := []string{joinAddress, joinCode, fingerprintF, presentedFP}
	if rc := replicaJoin(c, args, refusingReader{t}, false, &out, &errOut); rc == 0 {
		t.Error("a demotion with nothing to confirm on exited 0")
	}
	if rec.joins != 0 {
		t.Errorf("%d pairings were sent with no confirmation possible", rec.joins)
	}
	if !strings.Contains(errOut.String(), "--yes") {
		t.Errorf("the refusal does not name the flag that would confirm it:\n%s", errOut.String())
	}
}

// --yes is about the data this join discards, so it may skip that question. It
// may never skip the fingerprint check, which is about who is on the wire.
func TestYesSkipsTheDemotionConfirmationButNotTheFingerprint(t *testing.T) {
	c, rec := startNodeServer(t, "primary")
	var out, errOut bytes.Buffer
	if rc := replicaJoin(c, []string{joinAddress, joinCode, "--yes"}, strings.NewReader("no\n"), true, &out, &errOut); rc == 0 {
		t.Fatal("--yes accepted a fingerprint the operator declined")
	}
	if rec.joins != 0 {
		t.Fatalf("%d pairings were sent after a declined fingerprint", rec.joins)
	}

	c2, rec2 := startNodeServer(t, "primary")
	var out2, errOut2 bytes.Buffer
	args := []string{joinAddress, joinCode, fingerprintF, presentedFP, "--yes"}
	if rc := replicaJoin(c2, args, refusingReader{t}, false, &out2, &errOut2); rc != 0 {
		t.Fatalf("exit = %d, stderr = %s", rc, errOut2.String())
	}
	if rec2.joins != 1 {
		t.Fatalf("a confirmed scripted demotion sent %d pairings, want 1", rec2.joins)
	}
}

// The verb has to be reachable, and it takes no positional arguments.
func TestPromoteIsDispatched(t *testing.T) {
	c, _ := startNodeServer(t, "replica")
	var out, errOut bytes.Buffer
	if rc := replicaCmd(c, []string{"promote", "--yes"}, &out, &errOut); rc != 0 {
		t.Fatalf("replica promote exit = %d, stderr = %s", rc, errOut.String())
	}
	if strings.Contains(errOut.String(), "unknown replica subcommand") {
		t.Errorf("promote is not dispatched:\n%s", errOut.String())
	}
}
