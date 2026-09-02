package app

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/Busness-app/kydns-server/internal/config"
	"github.com/Busness-app/kydns-server/internal/policy"
	"github.com/Busness-app/kydns-server/internal/store"
)

// freePorts reserves n distinct ports. Every reservation is held open until
// all are chosen: closing one before taking the next lets the kernel hand back
// the same number, which silently collides the DNS and admin listeners.
//
// Each port is reserved on both UDP and TCP, because the DNS server binds both.
func freePorts(t *testing.T, n int) []int {
	t.Helper()
	var (
		ports []int
		udps  []net.PacketConn
		tcps  []net.Listener
	)
	for len(ports) < n {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := pc.LocalAddr().(*net.UDPAddr).Port
		l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			pc.Close() // TCP side taken; try another
			continue
		}
		udps, tcps, ports = append(udps, pc), append(tcps, l), append(ports, port)
	}
	for i := range udps {
		udps[i].Close()
		tcps[i].Close()
	}
	return ports
}

func freePort(t *testing.T) int {
	t.Helper()
	return freePorts(t, 1)[0]
}

func waitForHTTP(t *testing.T, url string) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if resp, err := http.Get(url); err == nil {
			resp.Body.Close()
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("server at %s never became ready", url)
}

// waitForFile reads a file the daemon writes asynchronously at startup.
func waitForFile(t *testing.T, path string) string {
	t.Helper()
	for i := 0; i < 200; i++ {
		if b, err := os.ReadFile(path); err == nil {
			return strings.TrimSpace(string(b))
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("%s was never written", path)
	return ""
}

// postStatus is postJSON for calls a test expects to be refused.
func postStatus(t *testing.T, url, token, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequest("POST", url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func postJSON(t *testing.T, url, token, body string) {
	t.Helper()
	req, err := http.NewRequest("POST", url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST %s = %d: %s", url, resp.StatusCode, b)
	}
}

func writeConfig(t *testing.T, dir string, extra string) (cfgPath string, dnsPort, adminPort int) {
	t.Helper()
	p := freePorts(t, 2)
	dnsPort, adminPort = p[0], p[1]
	quietBlacklists(t, dir)
	return writeConfigOn(t, dir, dnsPort, adminPort, extra), dnsPort, adminPort
}

// quietBlacklists disables the built-in list before any daemon opens this data
// dir. Every start seeds that list enabled and the refresher fetches it on the
// spot, so an untouched dir downloads several megabytes from the internet and
// inserts a hundred thousand rows — per daemon, in a package that starts a lot
// of them. Seeding here rather than disabling afterwards means the daemon's own
// SeedBuiltins finds the name and leaves it alone.
//
// This is the test path only: a real first run still gets filtering on.
func quietBlacklists(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "kydns.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := policy.SeedBuiltins(st); err != nil {
		t.Fatal(err)
	}
	lists, err := st.BlacklistListMetas()
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range lists {
		l.Enabled = false
		if _, err := st.PutBlacklistList(l); err != nil {
			t.Fatal(err)
		}
	}
}

// writeConfigOn rewrites a node's config on the ports it is already using, so
// a restart keeps the addresses an operator would keep across one.
func writeConfigOn(t *testing.T, dir string, dnsPort, adminPort int, extra string) (cfgPath string) {
	t.Helper()
	cfgPath = filepath.Join(dir, "kydns.yaml")
	body := fmt.Sprintf(`
data_dir: %s
dns:
  listen: "127.0.0.1:%d"
  private_domain: home.arpa
  reverse_zones: ["192.168.1.0/24"]
  allow_query: ["127.0.0.0/8"]
admin:
  listen: "127.0.0.1:%d"
%s`, dir, dnsPort, adminPort, extra)
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath
}

// The whole point of Plan 1: add a service over HTTP, resolve it over DNS.
func TestEndToEndAddServiceThenResolve(t *testing.T) {
	dir := t.TempDir()
	cfg, dnsPort, adminPort := writeConfig(t, dir, "")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errs := make(chan error, 1)
	go func() { errs <- Serve(ctx, cfg, nil) }()

	base := fmt.Sprintf("http://127.0.0.1:%d", adminPort)
	waitForHTTP(t, base+"/api/v1/healthz")
	token := waitForFile(t, filepath.Join(dir, "bootstrap-token"))

	postJSON(t, base+"/api/v1/services", token,
		`{"name":"kypost","addresses":[{"address":"192.168.1.20"}],"aliases":["webmail"]}`)

	c := &dns.Client{Net: "udp", Timeout: 3 * time.Second}
	server := fmt.Sprintf("127.0.0.1:%d", dnsPort)

	for _, name := range []string{"kypost.home.arpa.", "webmail.home.arpa."} {
		m := new(dns.Msg)
		m.SetQuestion(name, dns.TypeA)
		resp, _, err := c.Exchange(m, server)
		if err != nil {
			t.Fatalf("resolve %s: %v", name, err)
		}
		if len(resp.Answer) != 1 {
			t.Fatalf("%s answer = %v, want one A record", name, resp.Answer)
		}
		if got := resp.Answer[0].(*dns.A).A.String(); got != "192.168.1.20" {
			t.Errorf("%s = %s, want 192.168.1.20", name, got)
		}
	}

	// The reverse record is derived, not authored.
	m := new(dns.Msg)
	m.SetQuestion("20.1.168.192.in-addr.arpa.", dns.TypePTR)
	resp, _, err := c.Exchange(m, server)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Answer) != 1 || resp.Answer[0].(*dns.PTR).Ptr != "kypost.home.arpa." {
		t.Errorf("PTR = %v, want kypost.home.arpa.", resp.Answer)
	}

	cancel()
	select {
	case <-errs:
	case <-time.After(10 * time.Second):
		t.Error("Serve() did not return within 10s of context cancellation")
	}
}

// A view added over the API changes what a matching client is told, without a
// restart.
func TestEndToEndSplitHorizon(t *testing.T) {
	dir := t.TempDir()
	cfg, dnsPort, adminPort := writeConfig(t, dir, "")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go Serve(ctx, cfg, nil)

	base := fmt.Sprintf("http://127.0.0.1:%d", adminPort)
	waitForHTTP(t, base+"/api/v1/healthz")
	token := waitForFile(t, filepath.Join(dir, "bootstrap-token"))

	postJSON(t, base+"/api/v1/views", token, `{"name":"alt","subnets":["127.0.0.5/32"]}`)
	postJSON(t, base+"/api/v1/services", token,
		`{"name":"kypost","addresses":[{"address":"192.168.1.20"},{"address":"10.9.9.9","view":"alt"}]}`)

	server := fmt.Sprintf("127.0.0.1:%d", dnsPort)
	ask := func(source string) string {
		c := &dns.Client{
			Net: "udp", Timeout: 3 * time.Second,
			Dialer: &net.Dialer{LocalAddr: &net.UDPAddr{IP: net.ParseIP(source)}},
		}
		m := new(dns.Msg)
		m.SetQuestion("kypost.home.arpa.", dns.TypeA)
		resp, _, err := c.Exchange(m, server)
		if err != nil {
			t.Fatalf("resolve from %s: %v", source, err)
		}
		if len(resp.Answer) != 1 {
			t.Fatalf("from %s: answer = %v", source, resp.Answer)
		}
		return resp.Answer[0].(*dns.A).A.String()
	}
	if got := ask("127.0.0.1"); got != "192.168.1.20" {
		t.Errorf("default view = %s, want 192.168.1.20", got)
	}
	if got := ask("127.0.0.5"); got != "10.9.9.9" {
		t.Errorf("alt view = %s, want 10.9.9.9", got)
	}
}

// Tailscale clients are refused under the default, which is the whole reason
// the banner exists.
func TestTailscaleRefusedByDefault(t *testing.T) {
	dir := t.TempDir()
	p := freePorts(t, 2)
	dnsPort, adminPort := p[0], p[1]
	cfg := filepath.Join(dir, "kydns.yaml")
	body := fmt.Sprintf(`
data_dir: %s
dns:
  listen: "127.0.0.1:%d"
  allow_query: ["192.168.0.0/16"]
admin:
  listen: "127.0.0.1:%d"
`, dir, dnsPort, adminPort)
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	quietBlacklists(t, dir)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go Serve(ctx, cfg, nil)
	waitForHTTP(t, fmt.Sprintf("http://127.0.0.1:%d/api/v1/healthz", adminPort))

	c := &dns.Client{Net: "udp", Timeout: 3 * time.Second}
	m := new(dns.Msg)
	m.SetQuestion("kypost.home.arpa.", dns.TypeA)
	resp, _, err := c.Exchange(m, fmt.Sprintf("127.0.0.1:%d", dnsPort))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Rcode != dns.RcodeRefused {
		t.Errorf("Rcode = %s, want REFUSED for a loopback client outside the ACL",
			dns.RcodeToString[resp.Rcode])
	}
}

// A bad config must fail fast rather than starting half-configured.
func TestServeRejectsBadConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "kydns.yaml")
	os.WriteFile(cfg, []byte("dns:\n  listen: \":0\"\n"), 0o600) // no data_dir
	if err := Serve(context.Background(), cfg, nil); err == nil {
		t.Error("Serve() error = nil for a config with no data_dir")
	}
}

// A variable set once and forgotten otherwise overrides the file forever with
// nothing in the log to say why the file is being ignored.
func TestLogEnvOverridesNamesTheVariables(t *testing.T) {
	t.Setenv("KYDNS_REPLICATION_LISTEN", "0.0.0.0:8443")

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "kydns.yaml")
	if err := os.WriteFile(cfgPath, []byte("data_dir: "+dir+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	logEnvOverrides(cfg, slog.New(slog.NewTextHandler(&buf, nil)))

	if !strings.Contains(buf.String(), "KYDNS_REPLICATION_LISTEN") {
		t.Errorf("log %q does not name the variable that was applied", buf.String())
	}
}

func TestLogEnvOverridesSaysNothingWhenThereAreNone(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "kydns.yaml")
	if err := os.WriteFile(cfgPath, []byte("data_dir: "+dir+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	logEnvOverrides(cfg, slog.New(slog.NewTextHandler(&buf, nil)))

	if buf.Len() != 0 {
		t.Errorf("logged %q, want nothing when no variable was applied", buf.String())
	}
}

// The bootstrap token is minted once; a restart must not replace it.
func TestBootstrapTokenIsStable(t *testing.T) {
	dir := t.TempDir()
	cfg, _, adminPort := writeConfig(t, dir, "")

	ctx, cancel := context.WithCancel(context.Background())
	go Serve(ctx, cfg, nil)
	waitForHTTP(t, fmt.Sprintf("http://127.0.0.1:%d/api/v1/healthz", adminPort))
	first := waitForFile(t, filepath.Join(dir, "bootstrap-token"))
	cancel()
	time.Sleep(300 * time.Millisecond)

	cfg2, _, adminPort2 := writeConfig(t, dir, "")
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	go Serve(ctx2, cfg2, nil)
	waitForHTTP(t, fmt.Sprintf("http://127.0.0.1:%d/api/v1/healthz", adminPort2))

	second, err := os.ReadFile(filepath.Join(dir, "bootstrap-token"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(second)) != first {
		t.Error("restart minted a new bootstrap token, invalidating the operator's saved one")
	}
}
