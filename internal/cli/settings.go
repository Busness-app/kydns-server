package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

const settingsUsage = `usage:
  kydns settings get
  kydns settings set <key>=<value> [<key>=<value> ...] [--confirm-public <cidr>]

keys:
  private_domain, reverse_zones, upstreams, allow_query, allow_tailscale,
  ttl, cache_min_ttl, cache_max_ttl, negative_max_ttl, cache_entries,
  log_queries, log_client_ip, dhcp_lease_file, discovery_interval,
  health_interval, health_timeout, health_workers,
  dhcp_enabled, dhcp_interface, dhcp_range_start, dhcp_range_end,
  dhcp_gateway, dhcp_lease_seconds, dhcp_secondary_dns, dhcp_allow_foreign

lists take commas: upstreams=tls://1.1.1.1:853,tls://9.9.9.9:853`

// settingsKinds is how a key's value is encoded on the wire. The CLI has to
// know, because "120" as a JSON string is not the same request as 120. Keys
// mirror the json tags on settingsDTO in internal/adminapi/settings.go.
var settingsKinds = map[string]string{
	"private_domain": "string", "dhcp_lease_file": "string",
	"reverse_zones": "list", "upstreams": "list", "allow_query": "list",
	"allow_tailscale": "bool", "log_queries": "bool", "log_client_ip": "bool",
	"ttl": "int", "cache_min_ttl": "int", "cache_max_ttl": "int",
	"negative_max_ttl": "int", "cache_entries": "int",
	"discovery_interval": "int", "health_interval": "int",
	"health_timeout": "int", "health_workers": "int",
	"dhcp_enabled": "bool", "dhcp_interface": "string",
	"dhcp_range_start": "string", "dhcp_range_end": "string",
	"dhcp_gateway": "string", "dhcp_lease_seconds": "int",
	"dhcp_secondary_dns": "string", "dhcp_allow_foreign": "bool",
}

func settingsCmd(c *Client, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, settingsUsage)
		return 2
	}
	switch args[0] {
	case "get":
		return settingsGet(c, stdout, stderr)
	case "set":
		return settingsSet(c, args[1:], stdout, stderr)
	}
	fmt.Fprintln(stderr, settingsUsage)
	return 2
}

func settingsGet(c *Client, stdout, stderr io.Writer) int {
	var got map[string]any
	if err := c.Do("GET", "/api/v1/settings", nil, &got); err != nil {
		return fail(stderr, err)
	}
	keys := make([]string, 0, len(got))
	for k := range got {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		switch v := got[k].(type) {
		case []any:
			parts := make([]string, len(v))
			for i, e := range v {
				parts[i] = fmt.Sprint(e)
			}
			fmt.Fprintf(stdout, "%-20s %s\n", k, strings.Join(parts, ", "))
		case float64:
			fmt.Fprintf(stdout, "%-20s %s\n", k, strconv.FormatFloat(v, 'f', -1, 64))
		default:
			fmt.Fprintf(stdout, "%-20s %v\n", k, v)
		}
	}
	return 0
}

// settingsSet sends exactly the keys the operator named, in one PATCH. Sending
// only what was asked for means a set cannot clobber a concurrent edit made in
// the web UI.
func settingsSet(c *Client, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, settingsUsage)
		return 2
	}
	body := map[string]any{}
	for i := 0; i < len(args); i++ {
		if args[i] == "--confirm-public" {
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, "--confirm-public needs a CIDR")
				return 2
			}
			// Sent exactly as typed: never derived from the values being set,
			// so a set cannot manufacture its own guardrail bypass.
			body["confirm_public"] = args[i+1]
			i++
			continue
		}
		k, raw, ok := strings.Cut(args[i], "=")
		if !ok {
			fmt.Fprintf(stderr, "%q is not key=value\n", args[i])
			return 2
		}
		kind, known := settingsKinds[k]
		if !known {
			fmt.Fprintf(stderr, "unknown setting %q\n%s\n", k, settingsUsage)
			return 2
		}
		switch kind {
		case "int":
			n, err := strconv.Atoi(raw)
			if err != nil {
				fmt.Fprintf(stderr, "%s must be a whole number, got %q\n", k, raw)
				return 2
			}
			body[k] = n
		case "bool":
			b, err := strconv.ParseBool(raw)
			if err != nil {
				fmt.Fprintf(stderr, "%s must be true or false, got %q\n", k, raw)
				return 2
			}
			body[k] = b
		case "list":
			var out []string
			for _, part := range strings.Split(raw, ",") {
				if part = strings.TrimSpace(part); part != "" {
					out = append(out, part)
				}
			}
			// An explicit empty value clears the list rather than sending null.
			if out == nil {
				out = []string{}
			}
			body[k] = out
		default:
			body[k] = raw
		}
	}
	var got json.RawMessage
	if err := c.Do("PATCH", "/api/v1/settings", body, &got); err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintln(stdout, "settings updated")
	return 0
}
