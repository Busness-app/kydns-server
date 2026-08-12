package cli

import (
	"flag"
	"fmt"
	"io"
	"strings"
)

const blacklistUsage = `usage:
  kydns blacklist status
  kydns blacklist on|off
  kydns blacklist list
  kydns blacklist add <name> --url <https url> [--format domains|hosts|adblock] [--interval seconds]
  kydns blacklist rm <id>
  kydns blacklist refresh [id|all]
  kydns blacklist allow|deny <domain>
  kydns blacklist rules [allow|deny]
  kydns blacklist unrule <allow|deny> <id>
  kydns blacklist test <name>`

type blacklistListRow struct {
	ID              int64  `json:"id"`
	Name            string `json:"name"`
	URL             string `json:"url"`
	Format          string `json:"format"`
	Enabled         bool   `json:"enabled"`
	Builtin         bool   `json:"builtin"`
	IntervalSeconds int64  `json:"interval_seconds"`
	EntryCount      int    `json:"entry_count"`
	SkippedCount    int    `json:"skipped_count"`
	LastOKAt        int64  `json:"last_ok_at"`
	LastError       string `json:"last_error"`
}

type blacklistSettings struct {
	Enabled  bool `json:"enabled"`
	BlockTTL int  `json:"block_ttl"`
}

func blacklistCmd(c *Client, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, blacklistUsage)
		return 2
	}
	switch args[0] {
	case "status":
		return blacklistStatus(c, stdout, stderr)
	case "on", "off":
		if err := c.Do("PATCH", "/api/v1/blacklists/settings",
			map[string]any{"enabled": args[0] == "on"}, nil); err != nil {
			return fail(stderr, err)
		}
		fmt.Fprintf(stdout, "filtering %s\n", args[0])
		return 0
	case "list":
		return blacklistList(c, stdout, stderr)
	case "add":
		return blacklistAdd(c, args[1:], stdout, stderr)
	case "rm":
		if len(args) != 2 {
			fmt.Fprintln(stderr, "usage: kydns blacklist rm <id>")
			return 2
		}
		if err := c.Do("DELETE", "/api/v1/blacklists/lists/"+args[1], nil, nil); err != nil {
			return fail(stderr, err)
		}
		fmt.Fprintf(stdout, "removed list %s\n", args[1])
		return 0
	case "refresh":
		target := "all"
		if len(args) == 2 {
			target = args[1]
		}
		if err := c.Do("POST", "/api/v1/blacklists/lists/"+target+"/refresh", nil, nil); err != nil {
			return fail(stderr, err)
		}
		fmt.Fprintf(stdout, "refreshed %s\n", target)
		return 0
	case "allow", "deny":
		if len(args) != 2 {
			fmt.Fprintf(stderr, "usage: kydns blacklist %s <domain>\n", args[0])
			return 2
		}
		if err := c.Do("POST", "/api/v1/blacklists/rules/"+args[0],
			map[string]any{"domain": args[1]}, nil); err != nil {
			return fail(stderr, err)
		}
		fmt.Fprintf(stdout, "added %s rule for %s\n", args[0], args[1])
		return 0
	case "rules":
		kinds := []string{"deny", "allow"}
		if len(args) == 2 {
			kinds = []string{args[1]}
		}
		return blacklistRules(c, kinds, stdout, stderr)
	case "unrule":
		if len(args) != 3 {
			fmt.Fprintln(stderr, "usage: kydns blacklist unrule <allow|deny> <id>")
			return 2
		}
		if err := c.Do("DELETE", "/api/v1/blacklists/rules/"+args[1]+"/"+args[2], nil, nil); err != nil {
			return fail(stderr, err)
		}
		fmt.Fprintf(stdout, "removed %s rule %s\n", args[1], args[2])
		return 0
	case "test":
		if len(args) != 2 {
			fmt.Fprintln(stderr, "usage: kydns blacklist test <name>")
			return 2
		}
		var out struct {
			Name    string `json:"name"`
			Blocked bool   `json:"blocked"`
			Policy  string `json:"policy"`
		}
		if err := c.Do("GET", "/api/v1/blacklists/test?name="+args[1], nil, &out); err != nil {
			return fail(stderr, err)
		}
		if out.Blocked {
			fmt.Fprintf(stdout, "%s: blocked by %s\n", out.Name, out.Policy)
			return 0
		}
		fmt.Fprintf(stdout, "%s: allowed (%s)\n", out.Name, out.Policy)
		return 0
	}
	fmt.Fprintf(stderr, "kydns: unknown blacklist subcommand %q\n", args[0])
	return 2
}

func blacklistStatus(c *Client, stdout, stderr io.Writer) int {
	var set blacklistSettings
	if err := c.Do("GET", "/api/v1/blacklists/settings", nil, &set); err != nil {
		return fail(stderr, err)
	}
	state := "off"
	if set.Enabled {
		state = "on"
	}
	fmt.Fprintf(stdout, "filtering %s, blocks cached for %ds\n", state, set.BlockTTL)
	return blacklistList(c, stdout, stderr)
}

func blacklistList(c *Client, stdout, stderr io.Writer) int {
	var out struct {
		Lists []blacklistListRow `json:"lists"`
	}
	if err := c.Do("GET", "/api/v1/blacklists/lists", nil, &out); err != nil {
		return fail(stderr, err)
	}
	for _, l := range out.Lists {
		state := "off"
		if l.Enabled {
			state = "on"
		}
		note := ""
		switch {
		case l.LastError != "":
			// The stale snapshot is still serving; say so rather than "broken".
			note = " stale: " + l.LastError
		case l.LastOKAt == 0:
			note = " never loaded"
		}
		fmt.Fprintf(stdout, "%-6d %-20s %-4s %-8s %7d entries%s\n",
			l.ID, l.Name, state, l.Format, l.EntryCount, note)
	}
	return 0
}

func blacklistAdd(c *Client, args []string, stdout, stderr io.Writer) int {
	const usage = "usage: kydns blacklist add <name> --url <https url> [--format domains|hosts|adblock] [--interval seconds]"
	// The documented form puts the name before the flags, but flag.Parse stops
	// at the first positional. Peel the name off first.
	if len(args) < 1 || strings.HasPrefix(args[0], "-") {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	name := args[0]
	fs := flag.NewFlagSet("blacklist add", flag.ContinueOnError)
	fs.SetOutput(stderr)
	url := fs.String("url", "", "https source URL")
	format := fs.String("format", "domains", "domains, hosts or adblock")
	interval := fs.Int64("interval", 86400, "seconds between refreshes")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if *url == "" {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	// Checked here as well as on the server, so a typo fails before it is sent.
	if !strings.HasPrefix(*url, "https://") {
		fmt.Fprintln(stderr, "kydns: a list URL must be https")
		return 1
	}
	body := map[string]any{
		"name": name, "url": *url, "format": *format,
		"enabled": true, "interval_seconds": *interval,
	}
	if err := c.Do("POST", "/api/v1/blacklists/lists", body, nil); err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "added list %s\n", name)
	return 0
}

func blacklistRules(c *Client, kinds []string, stdout, stderr io.Writer) int {
	for _, kind := range kinds {
		var out struct {
			Rules []struct {
				ID     int64  `json:"id"`
				Kind   string `json:"kind"`
				Domain string `json:"domain"`
			} `json:"rules"`
		}
		if err := c.Do("GET", "/api/v1/blacklists/rules/"+kind, nil, &out); err != nil {
			return fail(stderr, err)
		}
		for _, r := range out.Rules {
			fmt.Fprintf(stdout, "%-6d %-6s %s\n", r.ID, r.Kind, r.Domain)
		}
	}
	return 0
}
