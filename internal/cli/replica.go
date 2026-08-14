package cli

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"
)

const replicaUsage = `usage:
  kydns replica invite
  kydns replica list
  kydns replica status
  kydns replica remove <node-id>
  kydns replica join <address> <code> [--fingerprint <fp>] [--yes]
  kydns replica promote [--yes]`

const joinUsage = "usage: kydns replica join <address> <code> [--fingerprint <fp>] [--yes]"

const promoteUsage = "usage: kydns replica promote [--yes]"

func replicaCmd(c *Client, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, replicaUsage)
		return 2
	}
	switch args[0] {
	case "invite":
		return replicaInvite(c, stdout, stderr)
	case "list":
		return replicaList(c, stdout, stderr)
	case "status":
		return replicaStatus(c, stdout, stderr)
	case "join":
		return replicaJoin(c, args[1:], os.Stdin, term.IsTerminal(int(os.Stdin.Fd())), stdout, stderr)
	case "promote":
		return replicaPromote(c, args[1:], os.Stdin, term.IsTerminal(int(os.Stdin.Fd())), stdout, stderr)
	case "remove":
		if len(args) != 2 {
			fmt.Fprintln(stderr, "usage: kydns replica remove <node-id>")
			return 2
		}
		if err := c.Do("DELETE", "/api/v1/replicas/"+args[1], nil, nil); err != nil {
			return fail(stderr, err)
		}
		fmt.Fprintf(stdout, "removed replica %s\n", args[1])
		return 0
	}
	fmt.Fprintf(stderr, "kydns: unknown replica subcommand %q\n", args[0])
	return 2
}

// replicaInvite prints the code and this node's fingerprint as one block.
// Pairing is the SSH model: the operator confirms the fingerprint on the
// replica before the code is sent, so both have to be in front of them at
// once. A code on its own is an invitation to skip the check.
func replicaInvite(c *Client, stdout, stderr io.Writer) int {
	var out struct {
		Code      string `json:"code"`
		NodeID    string `json:"node_id"`
		ExpiresAt int64  `json:"expires_at"`
	}
	if err := c.Do("POST", "/api/v1/replicas/invite", nil, &out); err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintln(stdout, "pairing invite for this node")
	fmt.Fprintln(stdout)
	fmt.Fprintf(stdout, "  code         %s\n", out.Code)
	fmt.Fprintf(stdout, "  fingerprint  %s\n", out.NodeID)
	fmt.Fprintf(stdout, "  expires      %s\n", unixTime(out.ExpiresAt))
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "On the replica, check the fingerprint it reports matches the one above")
	fmt.Fprintln(stdout, "before you enter the code. They must match exactly.")
	return 0
}

// replicaJoin pairs this node with a primary in two calls: one that dials and
// reports the key it was presented, and one that sends the code to exactly
// that key. The operator's decision sits between them, which is why they are
// two calls and not one: the CLI may be on a third machine entirely and cannot
// hold the connection being confirmed.
func replicaJoin(c *Client, args []string, in io.Reader, tty bool, stdout, stderr io.Writer) int {
	if len(args) < 2 || strings.HasPrefix(args[0], "-") || strings.HasPrefix(args[1], "-") {
		fmt.Fprintln(stderr, joinUsage)
		return 2
	}
	address, code := args[0], args[1]
	fs := flag.NewFlagSet("replica join", flag.ContinueOnError)
	fs.SetOutput(stderr)
	expected := fs.String("fingerprint", "", "the fingerprint the primary printed; compares it without prompting")
	yes := fs.Bool("yes", false, "skip the confirmation that this node's configuration will be replaced")
	if err := fs.Parse(args[2:]); err != nil {
		return 2
	}

	// No terminal and nothing to compare against is not permission to trust
	// whoever answers. Refused before anything is dialled.
	confirmed := normalizeFingerprint(*expected)
	if confirmed == "" && !tty {
		fmt.Fprintln(stderr, "kydns: there is no terminal here to confirm the primary's fingerprint on.")
		fmt.Fprintln(stderr, "Run kydns replica invite on the primary and pass what it prints as --fingerprint <fp>.")
		return 2
	}

	pair := pairingClient(c)
	var peeked struct {
		Fingerprint string `json:"fingerprint"`
	}
	if err := pair.Do("POST", "/api/v1/replica/pair/peek", map[string]string{"address": address}, &peeked); err != nil {
		return fail(stderr, err)
	}
	presented := normalizeFingerprint(peeked.Fingerprint)
	if presented == "" {
		return fail(stderr, fmt.Errorf("%s presented no key to confirm", address))
	}

	prompt := bufio.NewReader(in)
	if confirmed != "" {
		if presented != confirmed {
			fmt.Fprintf(stderr, "kydns: %s presented a fingerprint that is not the one you gave\n", address)
			fmt.Fprintf(stderr, "  presented  %s\n", presented)
			fmt.Fprintf(stderr, "  expected   %s\n", confirmed)
			codeWithheld(stderr)
			return 1
		}
	} else {
		// The operator has to read this and answer, so it goes where a redirected
		// stdout cannot swallow it: `kydns replica join addr code > join.log`
		// otherwise leaves them at a blank terminal with the value to compare
		// sitting in the file.
		fmt.Fprintf(stderr, "the node at %s presents fingerprint\n\n  %s\n\n", address, presented)
		fmt.Fprintln(stderr, "Compare it with the one kydns replica invite printed on the primary.")
		if !ask(prompt, stderr, "Do they match exactly?") {
			fmt.Fprintln(stderr, "kydns: fingerprint not confirmed")
			codeWithheld(stderr)
			return 1
		}
		confirmed = presented
	}

	if rc := confirmReplacement(c, address, prompt, tty, *yes, stdout, stderr); rc != 0 {
		codeWithheld(stderr)
		return rc
	}

	body := map[string]string{"address": address, "code": code, "fingerprint": confirmed}
	var out struct {
		PrimaryNodeID string `json:"primary_node_id"`
	}
	if err := pair.Do("POST", "/api/v1/replica/join", body, &out); err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) && apiErr.Code == "fingerprint_mismatch" {
			fmt.Fprintf(stderr, "kydns: the peer that answered does not hold the key you confirmed: %s\n", apiErr.Message)
			codeWithheld(stderr)
			return 1
		}
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "paired with %s\n", out.PrimaryNodeID)
	// Replacing, not adding: a demoted primary's file may still name the node it
	// used to follow, and that address with this pin fails every poll. Removing
	// replication.listen is not optional either: the two keys together are a
	// fatal config error, so a demoted primary that keeps its listener will not
	// start at all.
	fmt.Fprintf(stdout, "\nSet replication.primary to %s, replacing any address already there,\n", address)
	fmt.Fprintln(stdout, "and remove replication.listen if this node had one: a node with both keys")
	fmt.Fprintln(stdout, "refuses to start. Then restart to start following it.")
	return 0
}

// confirmReplacement is the destructive half of joining, the one --yes covers:
// the first pull replaces everything this node serves. On a primary that is a
// demotion, so what goes is counted out in full and confirmed even where there
// is no terminal to ask on.
func confirmReplacement(c *Client, address string, prompt *bufio.Reader, tty, yes bool, stdout, stderr io.Writer) int {
	demoting, services, records, err := localSummary(c)
	if err != nil {
		return fail(stderr, err)
	}
	if !demoting {
		if yes || !tty {
			return 0
		}
		fmt.Fprintf(stderr, "\nJoining replaces this node's configuration with the one on %s.\n", address)
		if !ask(prompt, stderr, "Continue?") {
			fmt.Fprintln(stderr, "kydns: cancelled")
			return 1
		}
		return 0
	}

	fmt.Fprintf(stderr, "\nThis node is a primary. Joining makes it a replica, and its first pull\n")
	fmt.Fprintln(stderr, "discards everything it holds now:")
	fmt.Fprintln(stderr)
	fmt.Fprintf(stderr, "  services  %d\n", services)
	fmt.Fprintf(stderr, "  records   %d\n", records)
	fmt.Fprintf(stderr, "  follows   %s\n", address)
	fmt.Fprintln(stderr)
	if yes {
		return 0
	}
	if !tty {
		fmt.Fprintln(stderr, "kydns: there is no terminal here to confirm discarding this node's configuration on.")
		fmt.Fprintln(stderr, "Pass --yes if that is what you want.")
		return 2
	}
	if !ask(prompt, stderr, "Discard this node's configuration and follow "+address+"?") {
		fmt.Fprintln(stderr, "kydns: cancelled")
		return 1
	}
	return 0
}

// localSummary is what this node would lose by joining: whether it is a
// primary being demoted, and how much configuration is here to be replaced.
func localSummary(c *Client) (primary bool, services, records int, err error) {
	var status struct {
		Role string `json:"role"`
	}
	if err := c.Do("GET", "/api/v1/replica/status", nil, &status); err != nil {
		return false, 0, 0, err
	}
	if status.Role != "primary" {
		return false, 0, 0, nil
	}
	var svcs struct {
		Services []struct{} `json:"services"`
	}
	if err := c.Do("GET", "/api/v1/services", nil, &svcs); err != nil {
		return false, 0, 0, err
	}
	var recs struct {
		Records []struct{} `json:"records"`
	}
	if err := c.Do("GET", "/api/v1/records", nil, &recs); err != nil {
		return false, 0, 0, err
	}
	return true, len(svcs.Services), len(recs.Records), nil
}

// replicaPromote makes this node the primary. The confirmation says what the
// operator has to do to the old primary, because two primaries serving the
// same replicas is the one state this design can neither detect nor reconcile.
func replicaPromote(c *Client, args []string, in io.Reader, tty bool, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("replica promote", flag.ContinueOnError)
	fs.SetOutput(stderr)
	yes := fs.Bool("yes", false, "skip the confirmation")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, promoteUsage)
		return 2
	}

	if !*yes {
		// With the prompt, for the same reason as join: a redirected stdout must
		// not hide the question the operator is being asked.
		fmt.Fprintln(stderr, "Promoting this node stops it following its primary and lets it accept writes.")
		fmt.Fprintln(stderr, "The old primary must be demoted or rebuilt before it is switched back on:")
		fmt.Fprintln(stderr, "two primaries serving the same replicas cannot be detected or undone.")
		fmt.Fprintln(stderr, "Demote it with kydns replica join once this node is serving.")
		if !tty {
			fmt.Fprintln(stderr, "kydns: there is no terminal here to confirm the promotion on.")
			fmt.Fprintln(stderr, "Pass --yes if that is what you want.")
			return 2
		}
		if !ask(bufio.NewReader(in), stderr, "Promote this node to primary?") {
			fmt.Fprintln(stderr, "kydns: cancelled")
			return 1
		}
	}

	var out struct {
		Promoted bool   `json:"promoted"`
		Role     string `json:"role"`
	}
	if err := c.Do("POST", "/api/v1/replica/promote", nil, &out); err != nil {
		return fail(stderr, err)
	}
	if !out.Promoted {
		// The role this node actually has. A standalone node told it is "already
		// a primary" would be sent looking for replicas it never had.
		fmt.Fprintf(stdout, "nothing changed: this node is a %s, not a replica\n", out.Role)
		return 0
	}
	fmt.Fprintln(stdout, "this node is now the primary and accepts writes")
	fmt.Fprintln(stdout)
	// Promotion does not open a listener: the config key that would is
	// replication.listen, and a promoted replica's file does not have one. An
	// operator who repoints replicas first gets refused connections and nothing
	// to read about why.
	fmt.Fprintln(stdout, "Replicas cannot follow it yet. Set replication.listen in this node's config")
	fmt.Fprintln(stdout, "and restart it, then run kydns replica invite for each replica.")
	fmt.Fprintln(stdout, "Do not switch the old primary back on until it is demoted or rebuilt.")
	return 0
}

// codeWithheld says what did not happen. A refusal that only says "failed"
// leaves the operator wondering whether the code is now spent.
func codeWithheld(stderr io.Writer) {
	fmt.Fprintln(stderr, "The pairing code was not sent, so it is still good.")
	fmt.Fprintln(stderr, "Check the address; something may be between this node and the primary.")
}

// ask reads one answer on the terminal, which is stderr: stdout may be a file
// the operator is not looking at. Anything that is not an explicit yes is a no,
// and so is a closed input: silence must never be taken for consent.
func ask(in *bufio.Reader, terminal io.Writer, question string) bool {
	fmt.Fprintf(terminal, "%s [yes/no]: ", question)
	line, err := in.ReadString('\n')
	if err != nil && line == "" {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	}
	return false
}

// normalizeFingerprint accepts what an operator pasted. Fingerprints are lower
// case hex, so case and stray whitespace are not a mismatch.
func normalizeFingerprint(fp string) string {
	return strings.ToLower(strings.TrimSpace(fp))
}

// pairingClient is c with room for the server to dial a third machine. The
// server's own dial is bounded; this has to outlast it, or a slow primary
// looks like a broken command.
func pairingClient(c *Client) *Client {
	out := *c
	if c.HTTP != nil {
		hc := *c.HTTP
		hc.Timeout = time.Minute
		out.HTTP = &hc
	}
	return &out
}

// nodeStatus is /api/v1/replica/status as both commands below read it.
type nodeStatus struct {
	Role          string `json:"role"`
	PrimaryAddr   string `json:"primary_address"`
	PrimaryNodeID string `json:"primary_node_id"`
	NodeID        string `json:"node_id"`
	LastSyncUnix  int64  `json:"last_sync_unix"`
	LastVersion   int64  `json:"last_version"`
	LastError     string `json:"last_error"`
	Stale         bool   `json:"stale"`
}

// replicaStatus is what this node itself is doing. On a replica it is the only
// place the last error is readable: "unlinked on the primary" and "schema
// mismatch" both look like an unreachable primary without it.
func replicaStatus(c *Client, stdout, stderr io.Writer) int {
	var st nodeStatus
	if err := c.Do("GET", "/api/v1/replica/status", nil, &st); err != nil {
		return fail(stderr, err)
	}
	printNodeStatus(st, stdout)
	return 0
}

func printNodeStatus(st nodeStatus, stdout io.Writer) {
	fmt.Fprintf(stdout, "role         %s\n", st.Role)
	if st.NodeID != "" {
		fmt.Fprintf(stdout, "fingerprint  %s\n", st.NodeID)
	}
	if st.Role != "replica" {
		return
	}
	fmt.Fprintf(stdout, "follows      %s\n", st.PrimaryAddr)
	fmt.Fprintf(stdout, "last sync    %s\n", unixTime(st.LastSyncUnix))
	fmt.Fprintf(stdout, "version      %d\n", st.LastVersion)
	if st.Stale {
		fmt.Fprintln(stdout, "stale        yes, this node may be serving replaced configuration")
	}
	if st.LastError != "" {
		fmt.Fprintf(stdout, "last error   %s\n", st.LastError)
	}
}

func replicaList(c *Client, stdout, stderr io.Writer) int {
	// A replica serves no replicas, so listing them prints nothing at all. What
	// the operator wanted on that box is this node's own state.
	var st nodeStatus
	if err := c.Do("GET", "/api/v1/replica/status", nil, &st); err != nil {
		return fail(stderr, err)
	}
	if st.Role == "replica" {
		printNodeStatus(st, stdout)
		return 0
	}
	var out struct {
		ConfigVersion int64        `json:"config_version"`
		Replicas      []replicaRow `json:"replicas"`
	}
	if err := c.Do("GET", "/api/v1/replicas", nil, &out); err != nil {
		return fail(stderr, err)
	}
	for _, r := range out.Replicas {
		fmt.Fprintf(stdout, "%s  %-16s %-12s lag %-6s last sync %s\n",
			r.NodeID, r.Label, r.Status, r.lagText(), unixTime(r.LastSyncAt))
	}
	return 0
}

// replicaRow is one peer as the primary reports it.
type replicaRow struct {
	NodeID     string `json:"node_id"`
	Label      string `json:"label"`
	LastSyncAt int64  `json:"last_sync_at"`
	Lag        int64  `json:"lag"`
	Status     string `json:"status"`
}

// lagText is how far behind a peer is. A peer that has never synced is not
// "42 versions behind": it holds nothing, and the web renders that as a dash.
func (r replicaRow) lagText() string {
	if r.LastSyncAt == 0 {
		return "-"
	}
	return strconv.FormatInt(r.Lag, 10)
}

// unixTime renders a stored timestamp. Zero means it never happened, which
// must not print as a date in 1970.
func unixTime(sec int64) string {
	if sec == 0 {
		return "never"
	}
	return time.Unix(sec, 0).Format(time.RFC3339)
}
