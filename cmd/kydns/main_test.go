package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/yoshiofthewire/kydns-server/internal/cli"
	"github.com/yoshiofthewire/kydns-server/internal/web"
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
