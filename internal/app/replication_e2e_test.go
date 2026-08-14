package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/yoshiofthewire/kydns-server/internal/cli"
)

// e2eDeadline bounds every poll in this test. The pull loop has its own
// interval, so the only honest assertion is "eventually, and before this".
const e2eDeadline = 30 * time.Second

// node is one kydns process as an operator runs it: a data dir, a config on
// fixed ports, and a token for the admin API.
type node struct {
	dir     string
	cfg     string
	dnsPort int
	base    string
	token   string
	stop    func()
}

// start runs the daemon and waits for its admin API. The returned stop waits
// for Serve to return, so a restart finds its ports free.
func (n *node) start(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	errs := make(chan error, 1)
	go func() { errs <- Serve(ctx, n.cfg, nil) }()
	stopped := false
	n.stop = func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		select {
		case <-errs:
		case <-time.After(10 * time.Second):
			t.Error("Serve did not return within 10s of cancellation")
		}
	}
	t.Cleanup(func() { n.stop() })
	waitForHTTP(t, n.base+"/api/v1/healthz")
	n.token = waitForFile(t, filepath.Join(n.dir, "bootstrap-token"))
}

// restart is what the CLI tells an operator to do after joining or promoting.
func (n *node) restart(t *testing.T) {
	t.Helper()
	n.stop()
	n.start(t)
}

func (n *node) dnsAddr() string { return fmt.Sprintf("127.0.0.1:%d", n.dnsPort) }

// runCLI drives the real command-line client against one node, through the
// environment it reads in production.
func runCLI(t *testing.T, n *node, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	t.Setenv("KYDNS_URL", n.base)
	t.Setenv("KYDNS_TOKEN", n.token)
	var out, errOut strings.Builder
	code = cli.Run(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

// fieldAfter reads one labelled value out of CLI output, the way an operator
// reads it off the screen.
func fieldAfter(t *testing.T, out, label string) string {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if f := strings.Fields(line); len(f) == 2 && f[0] == label {
			return f[1]
		}
	}
	t.Fatalf("no %q line in:\n%s", label, out)
	return ""
}

func getJSON(t *testing.T, url, token string, out any) {
	t.Helper()
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s = %d: %s", url, resp.StatusCode, body)
	}
	if err := json.Unmarshal(body, out); err != nil {
		t.Fatalf("GET %s: %v in %s", url, err, body)
	}
}

// healthOf is one service's state on this node's own health surface.
func healthOf(t *testing.T, n *node, service string) string {
	t.Helper()
	var out struct {
		Health []struct {
			Name  string `json:"name"`
			State string `json:"state"`
		} `json:"health"`
	}
	getJSON(t, n.base+"/api/v1/health", n.token, &out)
	for _, h := range out.Health {
		if h.Name == service {
			return h.State
		}
	}
	return ""
}

func waitForHealth(t *testing.T, n *node, service, want string) {
	t.Helper()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	deadline := time.After(e2eDeadline)
	var got string
	for {
		if got = healthOf(t, n, service); got == want {
			return
		}
		select {
		case <-tick.C:
		case <-deadline:
			t.Fatalf("%s health on this node = %q, want %q", service, got, want)
		}
	}
}

// The whole feature, end to end, the way an operator meets it: pair two nodes
// through the CLI, lose the primary, and promote the survivor. Every claim
// about configuration is made against a resolved answer, because rows that
// arrive without the zone snapshot being rebuilt are not replication.
func TestOperatorPairsWritesFailsOverAndPromotes(t *testing.T) {
	// Reachable from both nodes for the whole test: the health assertions below
	// are about where a status came from, never about the target being down.
	probe := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer probe.Close()

	primaryDir, primaryNodeID := nodeDir(t, "orchard")
	secondDir, _ := nodeDir(t, "meadow")
	replAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))

	// A two-second probe cycle, so the primary has a health verdict to
	// replicate within the deadline rather than the default half-minute.
	primaryCfg, _, primaryAdmin := writeConfig(t, primaryDir,
		fmt.Sprintf("replication:\n  listen: %q\nhealth:\n  interval: 2\n  timeout: 1\n", replAddr))
	primary := &node{dir: primaryDir, cfg: primaryCfg,
		base: fmt.Sprintf("http://127.0.0.1:%d", primaryAdmin)}

	// 1. The second node starts standalone: no replication keys at all, which
	// is what a box an operator decides to pair already looks like.
	secondCfg, secondDNS, secondAdmin := writeConfig(t, secondDir, "")
	second := &node{dir: secondDir, cfg: secondCfg, dnsPort: secondDNS,
		base: fmt.Sprintf("http://127.0.0.1:%d", secondAdmin)}

	primary.start(t)
	second.start(t)

	// 2. Pairing. A standalone node holds no key to pair with, and the refusal
	// has to say which key to set and that a restart is needed.
	code, _, stderr := runCLI(t, second, "replica", "join", replAddr, "unused-code",
		"--fingerprint", primaryNodeID)
	if code == 0 {
		t.Fatalf("join on a standalone node succeeded; it has no replication identity to pair with")
	}
	if !strings.Contains(stderr, "replication.primary") || !strings.Contains(stderr, "restart before pairing") {
		t.Errorf("the refusal does not say what to configure and that it needs a restart:\n%s", stderr)
	}

	second.cfg = writeConfigOn(t, secondDir, secondDNS, secondAdmin,
		fmt.Sprintf("replication:\n  primary: %q\n", replAddr))
	second.restart(t)

	code, inviteOut, stderr := runCLI(t, primary, "replica", "invite")
	if code != 0 {
		t.Fatalf("replica invite = %d: %s", code, stderr)
	}
	inviteCode := fieldAfter(t, inviteOut, "code")
	fingerprint := fieldAfter(t, inviteOut, "fingerprint")
	if fingerprint != primaryNodeID {
		t.Fatalf("the invite reported fingerprint %q, want the primary's own key %q", fingerprint, primaryNodeID)
	}
	if inviteCode == fingerprint {
		t.Fatal("the invite printed the same value as code and fingerprint")
	}

	// The operator types the code into the other box, pinned to the key the
	// invite printed beside it.
	code, joinOut, stderr := runCLI(t, second, "replica", "join", replAddr, inviteCode,
		"--fingerprint", fingerprint)
	if code != 0 {
		t.Fatalf("replica join = %d: %s", code, stderr)
	}
	if !strings.Contains(joinOut, "paired with "+primaryNodeID) {
		t.Errorf("join does not report which node it paired with:\n%s", joinOut)
	}
	if !strings.Contains(joinOut, "Set replication.primary to "+replAddr) {
		t.Errorf("join does not tell the operator to point this node at the primary:\n%s", joinOut)
	}

	// The primary now lists the node that joined, which is the screen an
	// operator checks before trusting the pairing.
	code, listOut, stderr := runCLI(t, primary, "replica", "list")
	if code != 0 {
		t.Fatalf("replica list = %d: %s", code, stderr)
	}
	if !strings.Contains(listOut, "never_synced") {
		t.Errorf("a peer that has never pulled is not listed as never synced:\n%s", listOut)
	}

	// 3. A service written on the primary, before the replica has ever pulled.
	postJSON(t, primary.base+"/api/v1/services", primary.token,
		fmt.Sprintf(`{"name":"quarry","addresses":[{"address":"192.168.1.44"}],"aliases":["pressroom"],"check_url":%q}`,
			probe.URL))

	// Pairing alone does not start the pull loop: the joined node follows its
	// primary only once it restarts with replication.primary set.
	second.restart(t)
	waitForA(t, second.dnsAddr(), "quarry.home.arpa.", "192.168.1.44")

	// An alias is built by the zone snapshot, not stored as a name: it can only
	// answer if the pull rebuilt the snapshot rather than writing rows.
	if got := resolveA(t, second.dnsAddr(), "pressroom.home.arpa."); !slices.Contains(got, "192.168.1.44") {
		t.Errorf("alias on the replica = %v, want 192.168.1.44", got)
	}
	// Health comes from the primary, which is the node that owns the probe.
	waitForHealth(t, second, "quarry", "up")

	// 4. The replica refuses writes, and says where to send them.
	status, body := postStatus(t, second.base+"/api/v1/services", second.token,
		`{"name":"sawmill","addresses":[{"address":"192.168.1.55"}]}`)
	if status != http.StatusConflict {
		t.Fatalf("POST /api/v1/services on a replica = %d: %s", status, body)
	}
	if !strings.Contains(body, replAddr) {
		t.Errorf("the refusal does not name the primary to write to instead: %s", body)
	}
	if got, err := lookupA(second.dnsAddr(), "sawmill.home.arpa."); err != nil || len(got) != 0 {
		t.Errorf("the refused write answered %v (%v); nothing should have been stored", got, err)
	}

	// 5. The primary goes away. The replica keeps answering, and stops
	// claiming to know anything about health: stale-good health would report a
	// dead service as alive.
	primary.stop()
	if got := resolveA(t, second.dnsAddr(), "quarry.home.arpa."); !slices.Contains(got, "192.168.1.44") {
		t.Errorf("with the primary gone, the replica answered %v, want 192.168.1.44", got)
	}
	waitForHealth(t, second, "quarry", "unknown")

	// 6. Promotion, through the CLI, with the primary still down.
	code, promoteOut, stderr := runCLI(t, second, "replica", "promote", "--yes")
	if code != 0 {
		t.Fatalf("replica promote = %d: %s", code, stderr)
	}
	if !strings.Contains(promoteOut, "replication.listen") {
		t.Errorf("promotion does not say that replicas cannot follow this node yet:\n%s", promoteOut)
	}
	postJSON(t, second.base+"/api/v1/services", second.token,
		`{"name":"foundry","addresses":[{"address":"192.168.1.66"}]}`)
	waitForA(t, second.dnsAddr(), "foundry.home.arpa.", "192.168.1.66")

	// 7. A promoted node comes back a primary. Promotion is recorded in the
	// database, and replication.primary is still in its config file.
	second.restart(t)
	var st struct {
		Role string `json:"role"`
	}
	getJSON(t, second.base+"/api/v1/replica/status", second.token, &st)
	if st.Role != "primary" {
		t.Fatalf("after a restart the promoted node reports role %q, want primary", st.Role)
	}
	postJSON(t, second.base+"/api/v1/services", second.token,
		`{"name":"tannery","addresses":[{"address":"192.168.1.77"}]}`)
	waitForA(t, second.dnsAddr(), "tannery.home.arpa.", "192.168.1.77")
	// What it pulled before the outage is still what it serves.
	if got := resolveA(t, second.dnsAddr(), "quarry.home.arpa."); !slices.Contains(got, "192.168.1.44") {
		t.Errorf("the promoted node answered %v for the replicated name, want 192.168.1.44", got)
	}
}
