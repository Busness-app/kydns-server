package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Fixture values are chosen so no assertion can be satisfied by the wrong one:
// the two fingerprints share no substring with each other or with the code.
const (
	joinAddress = "primary.example:8443"
	joinCode    = "K7QP2M9XTV4RB3ZC"
	presentedFP = "1a2b3c4d5e6f70819200aabbccddeeff1a2b3c4d5e6f70819200aabbccddeeff"
	mistypedFP  = "99887766554433221100ffeeddccbbaa99887766554433221100ffeeddccbbaa"
	// A whole phrase, not a word: a short one could be matched by an unrelated
	// sentence in the same output.
	warnBetween  = "may be between this node and"
	fingerprintF = "--fingerprint"
)

// joinRecorder is the server the CLI talks to. It remembers every code it was
// handed, because asserting only that the command failed would pass even if
// the code had been sent and then refused.
type joinRecorder struct {
	peeks     []string
	codes     []string
	joinFPs   []string
	joinReply func(w http.ResponseWriter)
}

func startJoinServer(t *testing.T) (*Client, *joinRecorder) {
	t.Helper()
	rec := &joinRecorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Address     string `json:"address"`
			Code        string `json:"code"`
			Fingerprint string `json:"fingerprint"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		switch r.URL.Path {
		case "/api/v1/replica/pair/peek":
			rec.peeks = append(rec.peeks, body.Address)
			// A peek carries no code, and a peek handler that received one would
			// be recorded here beside the joins.
			if body.Code != "" {
				rec.codes = append(rec.codes, body.Code)
			}
			json.NewEncoder(w).Encode(map[string]string{"fingerprint": presentedFP})
		case "/api/v1/replica/status":
			// This node is not a primary, so joining it is not a demotion and the
			// summary that names what a demotion discards never runs.
			json.NewEncoder(w).Encode(map[string]string{"role": "replica"})
		case "/api/v1/replica/join":
			rec.codes = append(rec.codes, body.Code)
			rec.joinFPs = append(rec.joinFPs, body.Fingerprint)
			if rec.joinReply != nil {
				rec.joinReply(w)
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"primary_node_id": presentedFP})
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return &Client{BaseURL: srv.URL, Token: "t", HTTP: srv.Client()}, rec
}

// refusingReader fails the test if the command reads from it. A scripted join
// must not consult the terminal at all.
type refusingReader struct{ t *testing.T }

func (r refusingReader) Read([]byte) (int, error) {
	r.t.Error("the command read from standard input when it had no prompt to ask")
	return 0, io.EOF
}

// The interactive path: the fingerprint is shown, the operator confirms it, and
// only then does the code travel.
func TestJoinPromptsAndPairsOnConfirmation(t *testing.T) {
	c, rec := startJoinServer(t)
	var out, errOut bytes.Buffer

	// Two answers: the fingerprint, then the confirmation --yes would skip.
	if rc := replicaJoin(c, []string{joinAddress, joinCode}, strings.NewReader("yes\nyes\n"), true, &out, &errOut); rc != 0 {
		t.Fatalf("exit = %d, stderr = %s", rc, errOut.String())
	}
	if len(rec.peeks) != 1 || rec.peeks[0] != joinAddress {
		t.Fatalf("peeked %q, want one peek at %q", rec.peeks, joinAddress)
	}
	// Shown before the question, not merely somewhere in the output: the same
	// fingerprint is printed again on success, which would satisfy a bare
	// "contains" no matter what the operator was asked to confirm.
	shown, asked := strings.Index(out.String(), presentedFP), strings.Index(out.String(), "[yes/no]")
	if shown < 0 || asked < 0 || shown > asked {
		t.Errorf("the fingerprint was not shown before the operator was asked to confirm it:\n%s", out.String())
	}
	if len(rec.codes) != 1 || rec.codes[0] != joinCode {
		t.Fatalf("primary received codes %q, want exactly the one the operator typed", rec.codes)
	}
	if len(rec.joinFPs) != 1 || rec.joinFPs[0] != presentedFP {
		t.Fatalf("join carried fingerprint %q, want the confirmed %q", rec.joinFPs, presentedFP)
	}
}

// A scripted join compares without asking, and never touches the terminal.
func TestJoinWithMatchingFingerprintNeedsNoPrompt(t *testing.T) {
	c, rec := startJoinServer(t)
	var out, errOut bytes.Buffer

	args := []string{joinAddress, joinCode, fingerprintF, presentedFP}
	if rc := replicaJoin(c, args, refusingReader{t}, false, &out, &errOut); rc != 0 {
		t.Fatalf("exit = %d, stderr = %s", rc, errOut.String())
	}
	if len(rec.codes) != 1 || rec.codes[0] != joinCode {
		t.Fatalf("primary received codes %q, want exactly the one supplied", rec.codes)
	}
	if len(rec.joinFPs) != 1 || rec.joinFPs[0] != presentedFP {
		t.Fatalf("join carried fingerprint %q, want %q", rec.joinFPs, presentedFP)
	}
}

// The whole point of the ordering: a fingerprint that does not match what the
// primary printed means the code is never sent anywhere.
func TestJoinWithMismatchedFingerprintSendsNoCode(t *testing.T) {
	for _, tty := range []bool{false, true} {
		c, rec := startJoinServer(t)
		var out, errOut bytes.Buffer

		args := []string{joinAddress, joinCode, fingerprintF, mistypedFP}
		// "yes" on the terminal must not rescue a mismatch either.
		if rc := replicaJoin(c, args, strings.NewReader("yes\nyes\n"), tty, &out, &errOut); rc == 0 {
			t.Fatalf("tty=%v: a mismatched fingerprint exited 0", tty)
		}
		if len(rec.codes) != 0 {
			t.Fatalf("tty=%v: primary received codes %q after a mismatch; nothing may be sent", tty, rec.codes)
		}
		if len(rec.joinFPs) != 0 {
			t.Fatalf("tty=%v: a join was sent after a mismatch: %q", tty, rec.joinFPs)
		}
		// Both values, so the operator can see which digit they mistyped.
		for _, want := range []string{presentedFP, mistypedFP} {
			if !strings.Contains(errOut.String(), want) {
				t.Errorf("tty=%v: the refusal does not show %s:\n%s", tty, want, errOut.String())
			}
		}
	}
}

// No terminal and no expected fingerprint is not a licence to trust whoever
// answered. It is a refusal that says which to supply.
func TestJoinWithoutTTYOrFingerprintRefuses(t *testing.T) {
	c, rec := startJoinServer(t)
	var out, errOut bytes.Buffer

	if rc := replicaJoin(c, []string{joinAddress, joinCode}, refusingReader{t}, false, &out, &errOut); rc == 0 {
		t.Fatal("a join with nothing to confirm the fingerprint against exited 0")
	}
	if len(rec.codes) != 0 {
		t.Fatalf("primary received codes %q with no confirmation possible", rec.codes)
	}
	if !strings.Contains(errOut.String(), fingerprintF) {
		t.Errorf("the refusal does not name the flag to supply:\n%s", errOut.String())
	}
}

// --yes skips the "this node's configuration will be replaced" question and
// nothing else. Skipping the fingerprint check would reopen the exact
// man-in-the-middle this design closes.
func TestYesFlagDoesNotSkipTheFingerprintCheck(t *testing.T) {
	c, rec := startJoinServer(t)
	var out, errOut bytes.Buffer

	args := []string{joinAddress, joinCode, "--yes"}
	if rc := replicaJoin(c, args, strings.NewReader("no\n"), true, &out, &errOut); rc == 0 {
		t.Fatal("--yes accepted the fingerprint the operator declined")
	}
	if len(rec.codes) != 0 {
		t.Fatalf("primary received codes %q after a declined fingerprint", rec.codes)
	}

	// An input that closes without answering is not an answer. Silence taken
	// for consent would pair with whatever a cron job happened to dial.
	cEOF, recEOF := startJoinServer(t)
	var outEOF, errEOF bytes.Buffer
	if rc := replicaJoin(cEOF, args, strings.NewReader(""), true, &outEOF, &errEOF); rc == 0 {
		t.Fatal("a prompt that was never answered was taken for a yes")
	}
	if len(recEOF.codes) != 0 {
		t.Fatalf("primary received codes %q for a question nobody answered", recEOF.codes)
	}

	// The same flag on the same command still saves the operator the second
	// question: one answer is enough to get through.
	c2, rec2 := startJoinServer(t)
	var out2, errOut2 bytes.Buffer
	if rc := replicaJoin(c2, args, strings.NewReader("yes\n"), true, &out2, &errOut2); rc != 0 {
		t.Fatalf("--yes still asked a second question: exit = %d, stderr = %s", rc, errOut2.String())
	}
	if len(rec2.codes) != 1 {
		t.Fatalf("primary received codes %q, want exactly one", rec2.codes)
	}
}

// A refused fingerprint may mean an attacker is in the path. It must not read
// like a dial that timed out.
func TestJoinReportsARejectedFingerprintDistinctly(t *testing.T) {
	rejected, network := &bytes.Buffer{}, &bytes.Buffer{}

	c, rec := startJoinServer(t)
	rec.joinReply = func(w http.ResponseWriter) {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{
			"code": "fingerprint_mismatch", "message": "the peer presented a different key",
		}})
	}
	var out bytes.Buffer
	args := []string{joinAddress, joinCode, fingerprintF, presentedFP}
	if rc := replicaJoin(c, args, refusingReader{t}, false, &out, rejected); rc == 0 {
		t.Fatal("a rejected fingerprint exited 0")
	}

	c2, rec2 := startJoinServer(t)
	rec2.joinReply = func(w http.ResponseWriter) {
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{
			"code": "pair_failed", "message": "dial primary.example:8443: connection refused",
		}})
	}
	var out2 bytes.Buffer
	if rc := replicaJoin(c2, args, refusingReader{t}, false, &out2, network); rc == 0 {
		t.Fatal("a failed dial exited 0")
	}

	if !strings.Contains(rejected.String(), warnBetween) {
		t.Errorf("a rejected fingerprint does not warn about what is on the wire:\n%s", rejected.String())
	}
	if strings.Contains(network.String(), warnBetween) {
		t.Errorf("a dial failure carries the man-in-the-middle warning:\n%s", network.String())
	}
	if !strings.Contains(network.String(), "connection refused") {
		t.Errorf("a dial failure does not report what went wrong:\n%s", network.String())
	}
}

// Both positionals are required, and the verb has to be reachable.
func TestJoinUsage(t *testing.T) {
	c := &Client{BaseURL: "http://127.0.0.1:1", Token: "t", HTTP: http.DefaultClient}
	for _, args := range [][]string{{"join"}, {"join", joinAddress}, {"join", fingerprintF, presentedFP}} {
		var out, errOut bytes.Buffer
		if rc := replicaCmd(c, args, &out, &errOut); rc != 2 {
			t.Errorf("replica %v exit = %d, want 2", args, rc)
		}
		if strings.Contains(errOut.String(), "unknown replica subcommand") {
			t.Errorf("join is not dispatched: %s", errOut.String())
		}
	}
}
