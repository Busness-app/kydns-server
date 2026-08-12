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
			if e.Error.Field != "" {
				return fmt.Errorf("%s: %s", e.Error.Field, e.Error.Message)
			}
			return fmt.Errorf("%s", e.Error.Message)
		}
		return fmt.Errorf("%s %s: %s", method, path, resp.Status)
	}
	if out != nil && len(raw) > 0 {
		return json.Unmarshal(raw, out)
	}
	return nil
}

// Run dispatches a subcommand and returns a process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "kydns: a subcommand is required")
		return 2
	}
	c := NewClient()
	switch args[0] {
	case "service":
		return serviceCmd(c, args[1:], stdout, stderr)
	case "record":
		return recordCmd(c, args[1:], stdout, stderr)
	case "view":
		return viewCmd(c, args[1:], stdout, stderr)
	case "token":
		return tokenCmd(c, args[1:], stdout, stderr)
	case "export":
		return exportCmd(c, args[1:], stdout, stderr)
	case "import":
		return importCmd(c, args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "kydns: unknown subcommand %q\n", args[0])
		return 2
	}
}

func fail(stderr io.Writer, err error) int {
	fmt.Fprintln(stderr, "kydns:", err)
	return 1
}

func serviceCmd(c *Client, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: kydns service add|list|rm")
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
		const addUsage = "usage: kydns service add <name> --address <ip> [--view v] [--alias a,b] [--check url] [--proxy ip] [--via-proxy]"
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
		if err := c.Do("POST", "/api/v1/services", body, nil); err != nil {
			return fail(stderr, err)
		}
		fmt.Fprintf(stdout, "added service %s\n", name)
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
