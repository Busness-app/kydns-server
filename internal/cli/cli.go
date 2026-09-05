// Package cli talks to a running server over the admin API. It never opens the
// database, so kydns works against a remote server for free.
package cli

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

func NewClient() *Client {
	base := os.Getenv("KYDNS_URL")
	if base == "" {
		base = "http://127.0.0.1:8053"
	}
	return &Client{
		BaseURL: strings.TrimSuffix(base, "/"),
		Token:   os.Getenv("KYDNS_TOKEN"),
		HTTP:    &http.Client{Timeout: 10 * time.Second},
	}
}

// APIError is the API's structured error. The code is carried, not only the
// message, because a caller sometimes has to act on which failure it was: a
// refused fingerprint is not a peer that failed to answer.
type APIError struct{ Code, Field, Message string }

func (e *APIError) Error() string {
	if e.Field != "" {
		return e.Field + ": " + e.Message
	}
	return e.Message
}

// Do sends a request and decodes the reply, surfacing the API's structured
// error so the CLI reports the same field name the UI would.
func (c *Client) Do(method, path string, body, out any) error {
	var rdr io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(buf)
	}
	req, err := http.NewRequest(method, c.BaseURL+path, rdr)
	if err != nil {
		return err
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		var e struct {
			Error struct{ Code, Message, Field string } `json:"error"`
		}
		if json.Unmarshal(raw, &e) == nil && e.Error.Message != "" {
			return &APIError{Code: e.Error.Code, Field: e.Error.Field, Message: e.Error.Message}
		}
		return fmt.Errorf("%s %s: %s", method, path, resp.Status)
	}
	if out != nil && len(raw) > 0 {
		return json.Unmarshal(raw, out)
	}
	return nil
}

func (c *Client) Download(path string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, c.BaseURL+path, nil)
	if err != nil {
		return nil, err
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("GET %s: %s: %s", path, resp.Status, strings.TrimSpace(string(raw)))
	}
	return raw, nil
}

// Command is one subcommand: the name it is invoked by, the one-line summary
// the binary's usage text prints for it, and what runs it.
type Command struct {
	Name    string
	Summary string
	Run     func(c *Client, args []string, stdout, stderr io.Writer) int
}

// Commands is every subcommand this package implements. It is the one list:
// Run dispatches on it and the binary routes and advertises on it, so a
// command cannot be implemented here and still be unreachable. It was two
// lists before, which is how "kydns blacklist" and then "kydns replica" ended
// up implemented but missing from the compiled binary.
var Commands = []Command{
	{"service", "manage services", serviceCmd},
	{"record", "manage records", recordCmd},
	{"view", "manage views", viewCmd},
	{"token", "manage API tokens", tokenCmd},
	{"blacklist", "manage domain filtering", blacklistCmd},
	{"settings", "view or change server settings", settingsCmd},
	{"dhcp", "show DHCP server state and current leases", dhcpCmd},
	{"replica", "manage replication and pairing", replicaCmd},
	{"export", "write registry contents to YAML or JSON", exportCmd},
	{"import", "load registry contents from YAML or JSON", importCmd},
	{"backup-drill", "verify a sealed recovery capsule can be built", backupDrillCmd},
	{"export-capsule", "write a sealed recovery capsule", exportCapsuleCmd},
	{"deposit", "deposit a sealed capsule with KyRecovery", depositCmd},
	{"backup-pin-key", "pin the suite recovery public key by hand", backupPinKeyCmd},
	{"backup-unpair", "forget the KyRecovery URL and token", backupUnpairCmd},
	{"backup-schedule", "set the automatic backup interval", backupScheduleCmd},
}

func backupDrillCmd(c *Client, args []string, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "usage: kydns backup-drill")
		return 2
	}
	var out any
	if err := c.Do(http.MethodPost, "/api/v1/backup/drill", nil, &out); err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintln(stdout, "backup drill passed")
	return 0
}

// backupPinKeyCmd reads the base64 public key from a file, never from argv: argv is
// world-readable in /proc and lands in shell history.
func backupPinKeyCmd(c *Client, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("backup-pin-key", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("public-key-file", "", "file holding the base64 recovery public key")
	k := fs.Int("threshold", 0, "custodian threshold (k)")
	n := fs.Int("total-shares", 0, "custodian shares (n)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *path == "" || fs.NArg() > 0 {
		fmt.Fprintln(stderr, "usage: kydns backup-pin-key --public-key-file path --threshold k --total-shares n")
		return 2
	}
	raw, err := os.ReadFile(*path)
	if err != nil {
		return fail(stderr, err)
	}
	var out struct {
		RecoveryKeyID string `json:"recovery_key_id"`
		Threshold     int    `json:"threshold"`
		TotalShares   int    `json:"total_shares"`
	}
	body := map[string]any{"public_key": strings.TrimSpace(string(raw)), "threshold": *k, "total_shares": *n}
	if err := c.Do(http.MethodPost, "/api/v1/backup/pin-key", body, &out); err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "pinned %s (%d-of-%d)\n", out.RecoveryKeyID, out.Threshold, out.TotalShares)
	return 0
}

func backupUnpairCmd(c *Client, args []string, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "usage: kydns backup-unpair")
		return 2
	}
	var out struct {
		Note string `json:"note"`
	}
	if err := c.Do(http.MethodDelete, "/api/v1/backup/pairing", nil, &out); err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintln(stdout, out.Note)
	return 0
}

func backupScheduleCmd(c *Client, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("backup-schedule", flag.ContinueOnError)
	fs.SetOutput(stderr)
	minutes := fs.Int64("minutes", -1, "backup interval in minutes; 0 turns it off")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *minutes < 0 || fs.NArg() > 0 {
		fmt.Fprintln(stderr, "usage: kydns backup-schedule --minutes n   (0 turns it off)")
		return 2
	}
	var out struct {
		IntervalSec int64 `json:"interval_sec"`
	}
	if err := c.Do(http.MethodPut, "/api/v1/backup/schedule", map[string]any{"interval_sec": *minutes * 60}, &out); err != nil {
		return fail(stderr, err)
	}
	if out.IntervalSec == 0 {
		fmt.Fprintln(stdout, "scheduled backups are off")
		return 0
	}
	fmt.Fprintf(stdout, "every %d minutes\n", out.IntervalSec/60)
	return 0
}

func depositCmd(c *Client, args []string, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "usage: kydns deposit")
		return 2
	}
	var out struct {
		CapsuleID string `json:"capsule_id"`
	}
	if err := c.Do(http.MethodPost, "/api/v1/backup/deposit", nil, &out); err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "deposited %s\n", out.CapsuleID)
	return 0
}

func exportCapsuleCmd(c *Client, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("export-capsule", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", "kydns-backup.kycap", "output path")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	raw, err := c.Download("/api/v1/backup/export-capsule")
	if err != nil {
		return fail(stderr, err)
	}
	if err := os.WriteFile(*out, raw, 0600); err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintln(stdout, *out)
	return 0
}

// Lookup finds a subcommand by name, so a caller can tell "not mine" from a
// command that ran and failed.
func Lookup(name string) *Command {
	for i := range Commands {
		if Commands[i].Name == name {
			return &Commands[i]
		}
	}
	return nil
}

// Run dispatches a subcommand and returns a process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "kydns: a subcommand is required")
		return 2
	}
	cmd := Lookup(args[0])
	if cmd == nil {
		fmt.Fprintf(stderr, "kydns: unknown subcommand %q\n", args[0])
		return 2
	}
	return cmd.Run(NewClient(), args[1:], stdout, stderr)
}

func fail(stderr io.Writer, err error) int {
	fmt.Fprintln(stderr, "kydns:", err)
	return 1
}

// flagWasSet reports whether the named flag was explicitly given, so a
// PATCH body can include a field only when the operator actually typed it —
// matched by name, not "was any flag seen", so a sibling flag can never
// arm a field it didn't set.
func flagWasSet(fs *flag.FlagSet, name string) bool {
	set := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}

func serviceCmd(c *Client, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: kydns service add|list|update|rm")
		return 2
	}
	switch args[0] {
	case "list":
		var out struct {
			Services []struct {
				ID        int64  `json:"id"`
				Name      string `json:"name"`
				Addresses []struct {
					Address string `json:"address"`
					View    string `json:"view"`
				} `json:"addresses"`
				ProxyAddress  string `json:"proxy_address"`
				RouteViaProxy bool   `json:"route_via_proxy"`
			} `json:"services"`
		}
		if err := c.Do("GET", "/api/v1/services", nil, &out); err != nil {
			return fail(stderr, err)
		}
		for _, s := range out.Services {
			suffix := ""
			if s.RouteViaProxy {
				suffix = " -> " + s.ProxyAddress
			}
			for _, a := range s.Addresses {
				view := a.View
				if view == "" {
					// Blank reads as broken; "all views" reads as everywhere.
					view = "all views"
				}
				fmt.Fprintf(stdout, "%-6d %-24s %-18s %s%s\n", s.ID, s.Name, a.Address, view, suffix)
			}
		}
		return 0

	case "add":
		const addUsage = "usage: kydns service add <name> --address <ip> [--view v] [--alias a,b] [--check url] [--proxy ip] [--via-proxy] [--mac aa:bb:cc:dd:ee:ff]"
		// The documented form puts the name before the flags, but flag.Parse
		// stops at the first positional. Peel the name off first.
		if len(args) < 2 || strings.HasPrefix(args[1], "-") {
			fmt.Fprintln(stderr, addUsage)
			return 2
		}
		name := args[1]
		fs := flag.NewFlagSet("service add", flag.ContinueOnError)
		fs.SetOutput(stderr)
		address := fs.String("address", "", "IP address")
		view := fs.String("view", "", "view name; empty means all views")
		alias := fs.String("alias", "", "comma-separated aliases")
		check := fs.String("check", "", "health check URL")
		proxy := fs.String("proxy", "", "send DNS for this service to this address instead")
		viaProxy := fs.Bool("via-proxy", false, "answer with --proxy rather than the service's own address")
		mac := fs.String("mac", "", "reserve this service's address for this MAC in the built-in DHCP server")
		if err := fs.Parse(args[2:]); err != nil {
			return 2
		}
		if *address == "" {
			fmt.Fprintln(stderr, addUsage)
			return 2
		}
		body := map[string]any{
			"name":      name,
			"addresses": []map[string]string{{"address": *address, "view": *view}},
		}
		if *check != "" {
			body["check_url"] = *check
		}
		if *alias != "" {
			body["aliases"] = strings.Split(*alias, ",")
		}
		if *proxy != "" {
			body["proxy_address"] = *proxy
		}
		if *viaProxy {
			body["route_via_proxy"] = true
		}
		// Sent as typed: the server normalizes and validates a MAC, so the CLI
		// has no second opinion to disagree with it from.
		if *mac != "" {
			body["mac"] = *mac
		}
		if err := c.Do("POST", "/api/v1/services", body, nil); err != nil {
			return fail(stderr, err)
		}
		fmt.Fprintf(stdout, "added service %s\n", name)
		return 0

	case "update":
		const updateUsage = "usage: kydns service update <id> --mac <aa:bb:cc:dd:ee:ff>   (an empty --mac gives the reservation up)"
		if len(args) < 2 || strings.HasPrefix(args[1], "-") {
			fmt.Fprintln(stderr, updateUsage)
			return 2
		}
		id := args[1]
		fs := flag.NewFlagSet("service update", flag.ContinueOnError)
		fs.SetOutput(stderr)
		mac := fs.String("mac", "", "reserve this service's address for this MAC; empty gives the reservation up")
		if err := fs.Parse(args[2:]); err != nil {
			return 2
		}
		// PATCH merges, so a body holding only what was typed cannot clear a
		// field this command was never asked about.
		asked := flagWasSet(fs, "mac")
		if !asked {
			fmt.Fprintln(stderr, updateUsage)
			return 2
		}
		if err := c.Do("PATCH", "/api/v1/services/"+id, map[string]any{"mac": *mac}, nil); err != nil {
			return fail(stderr, err)
		}
		fmt.Fprintf(stdout, "updated service %s\n", id)
		return 0

	case "rm":
		if len(args) != 2 {
			fmt.Fprintln(stderr, "usage: kydns service rm <id>")
			return 2
		}
		if err := c.Do("DELETE", "/api/v1/services/"+args[1], nil, nil); err != nil {
			return fail(stderr, err)
		}
		fmt.Fprintf(stdout, "removed service %s\n", args[1])
		return 0
	}
	fmt.Fprintf(stderr, "kydns: unknown service subcommand %q\n", args[0])
	return 2
}

func recordCmd(c *Client, args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "list" {
		var out struct {
			Records []struct {
				ID    int64  `json:"id"`
				Name  string `json:"name"`
				Type  string `json:"type"`
				Value string `json:"value"`
				View  string `json:"view"`
			} `json:"records"`
		}
		if err := c.Do("GET", "/api/v1/records", nil, &out); err != nil {
			return fail(stderr, err)
		}
		for _, r := range out.Records {
			view := r.View
			if view == "" {
				view = "all views"
			}
			fmt.Fprintf(stdout, "%-6d %-28s %-6s %-18s %s\n", r.ID, r.Name, r.Type, r.Value, view)
		}
		return 0
	}
	if len(args) >= 4 && args[0] == "add" {
		body := map[string]any{"name": args[1], "type": strings.ToUpper(args[2]), "value": args[3]}
		if len(args) == 5 {
			body["view"] = args[4]
		}
		if err := c.Do("POST", "/api/v1/records", body, nil); err != nil {
			return fail(stderr, err)
		}
		fmt.Fprintf(stdout, "added record %s\n", args[1])
		return 0
	}
	if len(args) == 2 && args[0] == "rm" {
		if err := c.Do("DELETE", "/api/v1/records/"+args[1], nil, nil); err != nil {
			return fail(stderr, err)
		}
		fmt.Fprintf(stdout, "removed record %s\n", args[1])
		return 0
	}
	fmt.Fprintln(stderr, "usage: kydns record add <name> <type> <value> [view] | list | rm <id>")
	return 2
}

func viewCmd(c *Client, args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "list" {
		var out struct {
			Views []struct {
				Name    string   `json:"name"`
				Subnets []string `json:"subnets"`
			} `json:"views"`
		}
		if err := c.Do("GET", "/api/v1/views", nil, &out); err != nil {
			return fail(stderr, err)
		}
		for _, v := range out.Views {
			fmt.Fprintf(stdout, "%-16s %s\n", v.Name, strings.Join(v.Subnets, ", "))
		}
		return 0
	}
	if len(args) == 3 && args[0] == "add" {
		body := map[string]any{"name": args[1], "subnets": strings.Split(args[2], ",")}
		if err := c.Do("POST", "/api/v1/views", body, nil); err != nil {
			return fail(stderr, err)
		}
		fmt.Fprintf(stdout, "added view %s\n", args[1])
		return 0
	}
	if len(args) == 2 && args[0] == "rm" {
		if err := c.Do("DELETE", "/api/v1/views/"+args[1], nil, nil); err != nil {
			return fail(stderr, err)
		}
		fmt.Fprintf(stdout, "removed view %s\n", args[1])
		return 0
	}
	fmt.Fprintln(stderr, "usage: kydns view add <name> <cidr[,cidr]> | list | rm <name>")
	return 2
}

func tokenCmd(c *Client, args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "list" {
		var out struct {
			Tokens []map[string]any `json:"tokens"`
		}
		if err := c.Do("GET", "/api/v1/tokens", nil, &out); err != nil {
			return fail(stderr, err)
		}
		for _, tk := range out.Tokens {
			fmt.Fprintf(stdout, "%-6v %s\n", tk["id"], tk["label"])
		}
		return 0
	}
	if len(args) == 2 && args[0] == "add" {
		var out struct {
			Token string `json:"token"`
		}
		if err := c.Do("POST", "/api/v1/tokens", map[string]any{"label": args[1]}, &out); err != nil {
			return fail(stderr, err)
		}
		// Shown once; the server keeps only a hash.
		fmt.Fprintln(stdout, out.Token)
		return 0
	}
	if len(args) == 2 && args[0] == "rm" {
		if err := c.Do("DELETE", "/api/v1/tokens/"+args[1], nil, nil); err != nil {
			return fail(stderr, err)
		}
		fmt.Fprintf(stdout, "revoked token %s\n", args[1])
		return 0
	}
	fmt.Fprintln(stderr, "usage: kydns token add <label> | list | rm <id>")
	return 2
}

func exportCmd(c *Client, args []string, stdout, stderr io.Writer) int {
	format := "yaml"
	if len(args) > 0 {
		format = args[0]
	}
	req, err := http.NewRequest("GET", c.BaseURL+"/api/v1/export?format="+format, nil)
	if err != nil {
		return fail(stderr, err)
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fail(stderr, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fail(stderr, fmt.Errorf("export: %s", resp.Status))
	}
	io.Copy(stdout, resp.Body)
	return 0
}

func importCmd(c *Client, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	fs.SetOutput(stderr)
	merge := fs.Bool("merge", false, "add to the existing registry")
	replace := fs.Bool("replace", false, "replace the registry contents")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *merge == *replace {
		fmt.Fprintln(stderr, "usage: kydns import --merge|--replace < file")
		return 2
	}
	mode := "merge"
	if *replace {
		mode = "replace"
	}
	body, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fail(stderr, err)
	}
	req, err := http.NewRequest("POST", c.BaseURL+"/api/v1/import?mode="+mode, bytes.NewReader(body))
	if err != nil {
		return fail(stderr, err)
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/yaml")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fail(stderr, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(resp.Body)
		return fail(stderr, fmt.Errorf("import: %s: %s", resp.Status, raw))
	}
	fmt.Fprintf(stdout, "imported (%s)\n", mode)
	return 0
}
