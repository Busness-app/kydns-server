package cli

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// blacklistServer records what the CLI sent and replies with canned JSON.
func blacklistServer(t *testing.T, routes map[string]string) (*httptest.Server, *[]string) {
	t.Helper()
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := new(bytes.Buffer)
		body.ReadFrom(r.Body)
		seen = append(seen, r.Method+" "+r.URL.RequestURI()+" "+strings.TrimSpace(body.String()))
		w.Header().Set("Content-Type", "application/json")
		if reply, ok := routes[r.Method+" "+r.URL.Path]; ok {
			w.Write([]byte(reply))
			return
		}
		w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)
	t.Setenv("KYDNS_URL", srv.URL)
	t.Setenv("KYDNS_TOKEN", "kydns_test")
	return srv, &seen
}

func runCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := Run(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestBlacklistStatus(t *testing.T) {
	_, seen := blacklistServer(t, map[string]string{
		"GET /api/v1/blacklists/settings": `{"enabled":true,"block_ttl":60}`,
		"GET /api/v1/blacklists/lists":    `{"lists":[{"id":1,"name":"steven-black","entry_count":3,"last_error":""}]}`,
	})
	code, out, errOut := runCLI(t, "blacklist", "status")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	for _, want := range []string{"on", "60", "steven-black", "3"} {
		if !strings.Contains(out, want) {
			t.Errorf("status output missing %q:\n%s", want, out)
		}
	}
	_ = seen
}

func TestBlacklistOffSendsPatch(t *testing.T) {
	_, seen := blacklistServer(t, nil)
	if code, _, errOut := runCLI(t, "blacklist", "off"); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if len(*seen) != 1 || !strings.HasPrefix((*seen)[0], "PATCH /api/v1/blacklists/settings") {
		t.Fatalf("sent %v, want one PATCH", *seen)
	}
	if !strings.Contains((*seen)[0], `"enabled":false`) {
		t.Errorf("body = %q, want enabled false", (*seen)[0])
	}
}

func TestBlacklistAddRequiresAnHTTPSURL(t *testing.T) {
	blacklistServer(t, nil)
	if code, _, _ := runCLI(t, "blacklist", "add", "custom"); code == 0 {
		t.Error("add without --url succeeded")
	}
	if code, _, _ := runCLI(t, "blacklist", "add", "custom", "--url", "http://x/y"); code == 0 {
		t.Error("add with a plain-http URL succeeded")
	}
}

func TestBlacklistAddSendsTheDefinition(t *testing.T) {
	_, seen := blacklistServer(t, map[string]string{
		"POST /api/v1/blacklists/lists": `{"id":7}`,
	})
	code, out, errOut := runCLI(t, "blacklist", "add", "custom",
		"--url", "https://lists.example/hosts", "--format", "hosts", "--interval", "3600")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if !strings.Contains(out, "custom") {
		t.Errorf("output = %q, want the list named", out)
	}
	sent := (*seen)[0]
	for _, want := range []string{`"name":"custom"`, `"url":"https://lists.example/hosts"`, `"format":"hosts"`, `"interval_seconds":3600`} {
		if !strings.Contains(sent, want) {
			t.Errorf("body %q missing %s", sent, want)
		}
	}
}

func TestBlacklistRuleCommands(t *testing.T) {
	_, seen := blacklistServer(t, map[string]string{
		"POST /api/v1/blacklists/rules/deny": `{"id":3}`,
		"GET /api/v1/blacklists/rules/deny":  `{"rules":[{"id":3,"kind":"deny","domain":"ads.example"}]}`,
		"GET /api/v1/blacklists/rules/allow": `{"rules":[]}`,
	})
	if code, _, errOut := runCLI(t, "blacklist", "deny", "ads.example"); code != 0 {
		t.Fatalf("deny: %s", errOut)
	}
	if !strings.Contains((*seen)[0], `"domain":"ads.example"`) {
		t.Errorf("sent %q", (*seen)[0])
	}
	code, out, errOut := runCLI(t, "blacklist", "rules")
	if code != 0 {
		t.Fatalf("rules: %s", errOut)
	}
	if !strings.Contains(out, "ads.example") || !strings.Contains(out, "deny") {
		t.Errorf("rules output = %q", out)
	}
}

func TestBlacklistTest(t *testing.T) {
	blacklistServer(t, map[string]string{
		"GET /api/v1/blacklists/test": `{"name":"ads.example","blocked":true,"policy":"steven-black"}`,
	})
	code, out, errOut := runCLI(t, "blacklist", "test", "ads.example")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if !strings.Contains(out, "blocked") || !strings.Contains(out, "steven-black") {
		t.Errorf("test output = %q, want the blocking list named", out)
	}
}

func TestBlacklistRefreshAll(t *testing.T) {
	_, seen := blacklistServer(t, nil)
	if code, _, errOut := runCLI(t, "blacklist", "refresh"); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if !strings.HasPrefix((*seen)[0], "POST /api/v1/blacklists/lists/all/refresh") {
		t.Errorf("sent %q, want the all-lists refresh", (*seen)[0])
	}
}

func TestBlacklistUnknownSubcommand(t *testing.T) {
	blacklistServer(t, nil)
	if code, _, _ := runCLI(t, "blacklist", "frobnicate"); code != 2 {
		t.Errorf("exit = %d, want 2", code)
	}
}
