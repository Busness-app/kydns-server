package cli

import (
	"fmt"
	"io"
	"time"
)

const replicaUsage = `usage:
  kydns replica invite
  kydns replica list
  kydns replica remove <node-id>`

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
