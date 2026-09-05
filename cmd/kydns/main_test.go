package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Busness-app/ky-primitives/capsule"
	"github.com/Busness-app/ky-primitives/recoverykey"
	"github.com/Busness-app/kydns-server/internal/cli"
	"github.com/Busness-app/kydns-server/internal/web"
)

func TestRunUnknownSubcommand(t *testing.T) {
	var out bytes.Buffer
	if code := run([]string{"bogus"}, &out); code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.Contains(out.String(), "usage:") {
		t.Errorf("output = %q, want usage text", out.String())
	}
}

// Every command the CLI implements has to be reachable from the binary and
// listed in the usage text. This reads cli.Commands and not the usage text on
// purpose: a command missing from both was invisible to the check below, which
// is how "kydns replica" shipped implemented but unroutable.
func TestEveryCLICommandRoutesAndIsAdvertised(t *testing.T) {
	for _, cmd := range cli.Commands {
		t.Run(cmd.Name, func(t *testing.T) {
			var out bytes.Buffer
			run([]string{cmd.Name}, &out)
			if strings.Contains(out.String(), "unknown command") {
				t.Errorf("%q is implemented but the binary does not route it", cmd.Name)
			}
			if !strings.Contains(usage, cmd.Name) {
				t.Errorf("%q is implemented but the usage text does not list it", cmd.Name)
			}
		})
	}
}

// The other direction: a command the usage text advertises has to route, which
// covers the ones main implements itself and cli.Commands does not know about.
func TestEveryAdvertisedCommandRoutes(t *testing.T) {
	for _, line := range strings.Split(usage, "\n") {
		name, _, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok || name == "" || strings.HasSuffix(name, ":") {
			continue
		}
		if name == "serve" {
			continue // would bind listeners
		}
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			run([]string{name}, &out)
			if strings.Contains(out.String(), "unknown command") {
				t.Errorf("%q is advertised but not routed", name)
			}
		})
	}
}

func TestRunNoArgsPrintsUsage(t *testing.T) {
	var out bytes.Buffer
	if code := run(nil, &out); code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
}

// The About popover and `kydns version` are the two places an operator reads
// the release from, and a bug report quoting one has to match the other.
func TestWebShowsTheStampedVersion(t *testing.T) {
	if web.Version != version {
		t.Errorf("web shows %q, binary reports %q", web.Version, version)
	}
}

func TestVersionCommandPrintsVersion(t *testing.T) {
	var out bytes.Buffer
	if code := run([]string{"version"}, &out); code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if got := strings.TrimSpace(out.String()); got != version {
		t.Errorf("output = %q, want %q", got, version)
	}
}

// The operator learns the target is unusable before custodians read their
// cards aloud, not after. capsule.Open refuses too, but only once the shares
// have been typed.
func TestRestoreRefusesNonEmptyTargetBeforeReadingShares(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "marker"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	capPath := filepath.Join(t.TempDir(), "KyDNS.kycap")
	if err := os.WriteFile(capPath, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	code, stderr := runCapturingStderr(t, []string{"restore", "--capsule", capPath, "--out", dir}, &out)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr, "restore directory must be empty") {
		t.Errorf("stderr = %q, want the empty-directory refusal", stderr)
	}
}

// Shares come on stdin so they never reach a shell history or a process list.
func TestRestoreRefusesASharePassedOnArgv(t *testing.T) {
	var out bytes.Buffer
	code := run([]string{"restore", "--capsule", "c.kycap", "--out", t.TempDir(), "ky2-something"}, &out)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.Contains(out.String(), "usage: kydns restore") {
		t.Errorf("output = %q, want the restore usage line", out.String())
	}
}

func TestRestoreRefusesAnotherProductBeforeReadingShares(t *testing.T) {
	key, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	raw, _, err := capsule.Seal("KySignOn", "test", []capsule.File{{Path: "data/foreign.db", Content: []byte("foreign"), Mode: 0o600}}, nil, nil, 2, 3, key.Public())
	if err != nil {
		t.Fatal(err)
	}
	capPath := filepath.Join(t.TempDir(), "foreign.kycap")
	if err := os.WriteFile(capPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	outDir := t.TempDir()
	var out bytes.Buffer
	code, stderr := runCapturingStderr(t, []string{"restore", "--capsule", capPath, "--out", outDir}, &out)
	if code != 1 || !strings.Contains(stderr, `capsule is for service "KySignOn", want "KyDNS"`) {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
	if entries, err := os.ReadDir(outDir); err != nil || len(entries) != 0 {
		t.Fatalf("wrong-service restore changed target: entries=%v err=%v", entries, err)
	}
}

func runCapturingStderr(t *testing.T, args []string, stdout io.Writer) (int, string) {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stderr
	os.Stderr = f
	code := run(args, stdout)
	os.Stderr = saved
	b, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	return code, string(b)
}
