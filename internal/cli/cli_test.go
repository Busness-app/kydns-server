package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestServiceListRendersUntaggedAsAllViews(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"services": []map[string]any{{
			"id": 1, "name": "kypost",
			"addresses": []map[string]string{
				{"address": "192.168.1.20", "view": ""},
				{"address": "100.101.102.103", "view": "tailnet"},
			},
		}}})
	}))
	defer srv.Close()

	c := &Client{BaseURL: srv.URL, Token: "t", HTTP: srv.Client()}
	var out, errOut bytes.Buffer
	if code := serviceCmd(c, []string{"list"}, &out, &errOut); code != 0 {
		t.Fatalf("exit = %d, stderr = %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "all views") {
		t.Errorf("untagged address not labelled:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "tailnet") {
		t.Errorf("tagged address missing:\n%s", out.String())
	}
}

// Routing changes what every client on the LAN resolves; the list must be
// able to show it, not just the edit path.
func TestServiceListShowsRouting(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"services": []map[string]any{{
			"id": 1, "name": "grafana",
			"addresses":       []map[string]string{{"address": "192.168.1.30", "view": ""}},
			"proxy_address":   "192.168.1.20",
			"route_via_proxy": true,
		}, {
			"id":        2,
			"name":      "printer",
			"addresses": []map[string]string{{"address": "192.168.1.50", "view": ""}},
		}}})
	}))
	defer srv.Close()

	c := &Client{BaseURL: srv.URL, Token: "t", HTTP: srv.Client()}
	var out, errOut bytes.Buffer
	if code := serviceCmd(c, []string{"list"}, &out, &errOut); code != 0 {
		t.Fatalf("exit = %d, stderr = %s", code, errOut.String())
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	var routed, unrouted string
	for _, l := range lines {
		if strings.Contains(l, "grafana") {
			routed = l
		}
		if strings.Contains(l, "printer") {
			unrouted = l
		}
	}
	if !strings.Contains(routed, "192.168.1.20") {
		t.Errorf("routed row missing the proxy address:\n%s", routed)
	}
	if strings.Contains(unrouted, "->") {
		t.Errorf("unrouted row shows a routing suffix:\n%s", unrouted)
	}
}

// A structured API error must surface with its field name, not a bare status.
func TestClientSurfacesFieldError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":{"code":"label_charset","field":"name","message":"label is invalid"}}`))
	}))
	defer srv.Close()

	c := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	err := c.Do("POST", "/api/v1/services", map[string]string{"name": "bad_name"}, nil)
	if err == nil {
		t.Fatal("Do() error = nil, want the API error")
	}
	if !strings.Contains(err.Error(), "name") || !strings.Contains(err.Error(), "label is invalid") {
		t.Errorf("err = %v, want the field and message", err)
	}
}

func TestServiceAddPostsBody(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"id":1}`))
	}))
	defer srv.Close()

	c := &Client{BaseURL: srv.URL, Token: "t", HTTP: srv.Client()}
	var out, errOut bytes.Buffer
	code := serviceCmd(c, []string{
		"add", "kypost", "--address", "100.101.102.103", "--view", "tailnet", "--alias", "webmail,mail",
	}, &out, &errOut)
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %s", code, errOut.String())
	}
	// The confirmation must name the service, not print a blank.
	if !strings.Contains(out.String(), "kypost") {
		t.Errorf("stdout = %q, want the service name", out.String())
	}
	if got["name"] != "kypost" {
		t.Errorf("name = %v", got["name"])
	}
	addrs, _ := got["addresses"].([]any)
	if len(addrs) != 1 {
		t.Fatalf("addresses = %v", got["addresses"])
	}
	first, _ := addrs[0].(map[string]any)
	if first["address"] != "100.101.102.103" || first["view"] != "tailnet" {
		t.Errorf("address entry = %v", first)
	}
	aliases, _ := got["aliases"].([]any)
	if len(aliases) != 2 {
		t.Errorf("aliases = %v", got["aliases"])
	}
}

func TestServiceAddPostsProxyFields(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"id":1}`))
	}))
	defer srv.Close()

	c := &Client{BaseURL: srv.URL, Token: "t", HTTP: srv.Client()}
	var out, errOut bytes.Buffer
	code := serviceCmd(c, []string{
		"add", "kypost", "--address", "192.168.1.30", "--proxy", "192.168.1.20", "--via-proxy",
	}, &out, &errOut)
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %s", code, errOut.String())
	}
	if got["proxy_address"] != "192.168.1.20" {
		t.Errorf("proxy_address = %v", got["proxy_address"])
	}
	if got["route_via_proxy"] != true {
		t.Errorf("route_via_proxy = %v", got["route_via_proxy"])
	}
}

// The reservation has to be settable where the service is defined, or the
// only way to get one is the web UI.
func TestServiceAddPostsMAC(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"id":1}`))
	}))
	defer srv.Close()

	c := &Client{BaseURL: srv.URL, Token: "t", HTTP: srv.Client()}
	var out, errOut bytes.Buffer
	code := serviceCmd(c, []string{
		"add", "kypost", "--address", "192.168.1.30", "--mac", "AA:BB:CC:DD:EE:FF",
	}, &out, &errOut)
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %s", code, errOut.String())
	}
	// Sent as typed; the server normalizes, so the CLI cannot disagree with it.
	if got["mac"] != "AA:BB:CC:DD:EE:FF" {
		t.Errorf("mac = %v, want the address as typed", got["mac"])
	}
}

func TestServiceAddOmitsAnEmptyMAC(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"id":1}`))
	}))
	defer srv.Close()

	c := &Client{BaseURL: srv.URL, Token: "t", HTTP: srv.Client()}
	var out, errOut bytes.Buffer
	serviceCmd(c, []string{"add", "kypost", "--address", "192.168.1.30"}, &out, &errOut)
	if _, ok := got["mac"]; ok {
		t.Errorf("body carries mac = %v with no --mac given", got["mac"])
	}
}

// Reserving an address for a service that already exists is the normal case:
// the service was defined long before DHCP was turned on.
func TestServiceUpdateSendsOnlyTheMAC(t *testing.T) {
	var got map[string]any
	var method, path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method, path = r.Method, r.URL.Path
		json.NewDecoder(r.Body).Decode(&got)
		w.Write([]byte(`{"id":7}`))
	}))
	defer srv.Close()

	c := &Client{BaseURL: srv.URL, Token: "t", HTTP: srv.Client()}
	var out, errOut bytes.Buffer
	if code := serviceCmd(c, []string{"update", "7", "--mac", "aa:bb:cc:dd:ee:ff"}, &out, &errOut); code != 0 {
		t.Fatalf("exit = %d, stderr = %s", code, errOut.String())
	}
	if method != "PATCH" || path != "/api/v1/services/7" {
		t.Fatalf("sent %s %s, want PATCH /api/v1/services/7", method, path)
	}
	if got["mac"] != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("mac = %v", got["mac"])
	}
	// Anything else in the body would be a field this command was never asked
	// about, sent back over whatever the operator changed elsewhere.
	if len(got) != 1 {
		t.Errorf("body = %v, want the mac alone", got)
	}
}

// An empty --mac is how a reservation is given up, so it has to be sent
// rather than treated as "no flag".
func TestServiceUpdateClearsTheMAC(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&got)
		w.Write([]byte(`{"id":7}`))
	}))
	defer srv.Close()

	c := &Client{BaseURL: srv.URL, Token: "t", HTTP: srv.Client()}
	var out, errOut bytes.Buffer
	if code := serviceCmd(c, []string{"update", "7", "--mac", ""}, &out, &errOut); code != 0 {
		t.Fatalf("exit = %d, stderr = %s", code, errOut.String())
	}
	if v, ok := got["mac"]; !ok || v != "" {
		t.Errorf("body = %v, want an explicit empty mac", got)
	}
}

func TestServiceUpdateNeedsAnIDAndAChange(t *testing.T) {
	c := &Client{BaseURL: "http://127.0.0.1:1", HTTP: http.DefaultClient}
	for _, args := range [][]string{{"update"}, {"update", "--mac", "aa:bb:cc:dd:ee:ff"}, {"update", "7"}} {
		var out, errOut bytes.Buffer
		if code := serviceCmd(c, args, &out, &errOut); code != 2 {
			t.Errorf("service %v = %d, want a usage error", args, code)
		}
	}
}

func TestServiceAddRequiresNameAndAddress(t *testing.T) {
	c := &Client{BaseURL: "http://127.0.0.1:1", HTTP: http.DefaultClient}
	var out, errOut bytes.Buffer
	if code := serviceCmd(c, []string{"add", "kypost"}, &out, &errOut); code == 0 {
		t.Error("service add without --address succeeded, want a usage error")
	}
}

func TestUnknownSubcommand(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := Run([]string{"nonsense"}, &out, &errOut); code != 2 {
		t.Errorf("exit = %d, want 2", code)
	}
}

func TestViewList(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"views": []map[string]any{
			{"name": "tailnet", "subnets": []string{"100.64.0.0/10"}},
		}})
	}))
	defer srv.Close()

	c := &Client{BaseURL: srv.URL, Token: "t", HTTP: srv.Client()}
	var out, errOut bytes.Buffer
	if code := viewCmd(c, []string{"list"}, &out, &errOut); code != 0 {
		t.Fatalf("exit = %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "100.64.0.0/10") {
		t.Errorf("view subnets missing:\n%s", out.String())
	}
}
