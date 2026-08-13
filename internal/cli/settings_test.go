package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// clientFor builds a Client pointed at a test server.
func clientFor(srv *httptest.Server) *Client {
	return &Client{BaseURL: srv.URL, Token: "t", HTTP: srv.Client()}
}

func TestSettingsGetPrints(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"private_domain":"home.arpa","ttl":60,"upstreams":["tls://1.1.1.1:853"]}`))
	}))
	defer srv.Close()

	var out, errOut bytes.Buffer
	if code := settingsCmd(clientFor(srv), []string{"get"}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	for _, want := range []string{"private_domain", "home.arpa", "ttl", "60"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output is missing %q:\n%s", want, out.String())
		}
	}
}

func TestSettingsSetSendsOnePatch(t *testing.T) {
	var got map[string]any
	var patches int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PATCH" {
			patches++
			json.NewDecoder(r.Body).Decode(&got)
		}
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	var out, errOut bytes.Buffer
	code := settingsCmd(clientFor(srv), []string{"set", "ttl=120", "log_queries=true"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	// One request, so a set cannot lose a concurrent edit from the UI.
	if patches != 1 {
		t.Errorf("sent %d PATCH requests, want 1", patches)
	}
	if got["ttl"] != float64(120) {
		t.Errorf("ttl: %v", got["ttl"])
	}
	if got["log_queries"] != true {
		t.Errorf("log_queries: %v (%T)", got["log_queries"], got["log_queries"])
	}
	// A key the operator did not name must not be in the body at all.
	if _, ok := got["private_domain"]; ok {
		t.Error("an unnamed key was sent, which would clobber a concurrent edit")
	}
}

func TestSettingsSetListValue(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&got)
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	var out, errOut bytes.Buffer
	settingsCmd(clientFor(srv), []string{"set", "upstreams=tls://1.1.1.1:853,tls://9.9.9.9:853"}, &out, &errOut)

	list, ok := got["upstreams"].([]any)
	if !ok || len(list) != 2 {
		t.Fatalf("upstreams: %#v", got["upstreams"])
	}
	if list[0] != "tls://1.1.1.1:853" {
		t.Errorf("order lost: %v", list)
	}
}

func TestSettingsSetRejectsUnknownKey(t *testing.T) {
	var out, errOut bytes.Buffer
	code := settingsCmd(&Client{}, []string{"set", "nonsense=1"}, &out, &errOut)
	if code == 0 {
		t.Fatal("an unknown key was accepted")
	}
	if !strings.Contains(errOut.String(), "nonsense") {
		t.Errorf("the error does not name the key: %s", errOut.String())
	}
}

func TestSettingsSetListValueClears(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&got)
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	var out, errOut bytes.Buffer
	code := settingsCmd(clientFor(srv), []string{"set", "reverse_zones="}, &out, &errOut)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	list, ok := got["reverse_zones"].([]any)
	if !ok {
		t.Fatalf("reverse_zones: %#v, want an array", got["reverse_zones"])
	}
	if len(list) != 0 {
		t.Errorf("reverse_zones: %v, want empty", list)
	}
}

func TestSettingsSetConfirmPublicSendsExactlyWhatWasTyped(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&got)
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	var out, errOut bytes.Buffer
	code := settingsCmd(clientFor(srv),
		[]string{"set", "allow_query=0.0.0.0/0", "--confirm-public", "0.0.0.0/0"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	if got["confirm_public"] != "0.0.0.0/0" {
		t.Errorf("confirm_public: %v, want the literal operator input", got["confirm_public"])
	}
}
