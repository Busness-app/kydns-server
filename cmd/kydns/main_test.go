package main

import (
	"bytes"
	"strings"
	"testing"
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

// Every command the usage text advertises has to route. A command listed here
// but missing from the switch is unreachable from the compiled binary, which is
// exactly how "kydns blacklist" went missing.
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
