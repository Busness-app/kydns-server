package cli

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/term"
)

const replicaUsage = `usage:
  kydns replica invite
  kydns replica list
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
		fmt.Fprintf(stdout, "the node at %s presents fingerprint\n\n  %s\n\n", address, presented)
		fmt.Fprintln(stdout, "Compare it with the one kydns replica invite printed on the primary.")
		if !ask(prompt, stdout, "Do they match exactly?") {
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
	fmt.Fprintf(stdout, "\npaired with %s\n", out.PrimaryNodeID)
	fmt.Fprintf(stdout, "Set replication.primary to %s and restart to start following it.\n", address)
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
		fmt.Fprintf(stdout, "\nJoining replaces this node's configuration with the one on %s.\n", address)
		if !ask(prompt, stdout, "Continue?") {
			fmt.Fprintln(stderr, "kydns: cancelled")
			return 1
		}
		return 0
	}

	fmt.Fprintf(stdout, "\nThis node is a primary. Joining makes it a replica, and its first pull\n")
	fmt.Fprintln(stdout, "discards everything it holds now:")
	fmt.Fprintln(stdout)
	fmt.Fprintf(stdout, "  services  %d\n", services)
	fmt.Fprintf(stdout, "  records   %d\n", records)
	fmt.Fprintf(stdout, "  follows   %s\n", address)
	fmt.Fprintln(stdout)
	if yes {
		return 0
	}
	if !tty {
		fmt.Fprintln(stderr, "kydns: there is no terminal here to confirm discarding this node's configuration on.")
		fmt.Fprintln(stderr, "Pass --yes if that is what you want.")
		return 2
	}
	if !ask(prompt, stdout, "Discard this node's configuration and follow "+address+"?") {
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
		fmt.Fprintln(stdout, "Promoting this node stops it following its primary and lets it accept writes.")
		fmt.Fprintln(stdout, "The old primary must be demoted or rebuilt before it is switched back on:")
		fmt.Fprintln(stdout, "two primaries serving the same replicas cannot be detected or undone.")
		fmt.Fprintln(stdout, "Demote it with kydns replica join once this node is serving.")
		if !tty {
			fmt.Fprintln(stderr, "kydns: there is no terminal here to confirm the promotion on.")
			fmt.Fprintln(stderr, "Pass --yes if that is what you want.")
			return 2
		}
		if !ask(bufio.NewReader(in), stdout, "Promote this node to primary?") {
			fmt.Fprintln(stderr, "kydns: cancelled")
			return 1
		}
	}

	var out struct {
		Promoted bool `json:"promoted"`
	}
	if err := c.Do("POST", "/api/v1/replica/promote", nil, &out); err != nil {
		return fail(stderr, err)
	}
	if !out.Promoted {
		fmt.Fprintln(stdout, "this node was already a primary; nothing changed")
		return 0
	}
	fmt.Fprintln(stdout, "this node is now the primary and accepts writes")
	fmt.Fprintln(stdout, "Point its replicas at it, and do not switch the old primary back on until it is demoted.")
	return 0
}

// codeWithheld says what did not happen. A refusal that only says "failed"
// leaves the operator wondering whether the code is now spent.
func codeWithheld(stderr io.Writer) {
	fmt.Fprintln(stderr, "The pairing code was not sent, so it is still good.")
	fmt.Fprintln(stderr, "Check the address; something may be between this node and the primary.")
}

// ask reads one answer. Anything that is not an explicit yes is a no, and so
// is a closed input: silence must never be taken for consent.
func ask(in *bufio.Reader, stdout io.Writer, question string) bool {
	fmt.Fprintf(stdout, "%s [yes/no]: ", question)
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

func replicaList(c *Client, stdout, stderr io.Writer) int {
	var out struct {
		ConfigVersion int64 `json:"config_version"`
		Replicas      []struct {
			NodeID     string `json:"node_id"`
			Label      string `json:"label"`
			LastSyncAt int64  `json:"last_sync_at"`
			Lag        int64  `json:"lag"`
			Status     string `json:"status"`
		} `json:"replicas"`
	}
	if err := c.Do("GET", "/api/v1/replicas", nil, &out); err != nil {
		return fail(stderr, err)
	}
	for _, r := range out.Replicas {
		fmt.Fprintf(stdout, "%s  %-16s %-12s lag %-6d last sync %s\n",
			r.NodeID, r.Label, r.Status, r.Lag, unixTime(r.LastSyncAt))
	}
	return 0
}

// unixTime renders a stored timestamp. Zero means it never happened, which
// must not print as a date in 1970.
func unixTime(sec int64) string {
	if sec == 0 {
		return "never"
	}
	return time.Unix(sec, 0).Format(time.RFC3339)
}
