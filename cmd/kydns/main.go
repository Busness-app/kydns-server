package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/Busness-app/ky-primitives/capsule"
	"github.com/Busness-app/ky-primitives/recoverykey"
	"github.com/Busness-app/ky-primitives/shamir"
	"github.com/Busness-app/kydns-server/internal/app"
	"github.com/Busness-app/kydns-server/internal/cli"
	"github.com/Busness-app/kydns-server/internal/web"
)

// version is set at link time with -X main.version. "dev" means someone built
// straight from a source tree, which is exactly what a bug report needs to say.
var version = "dev"

// The web UI prints the same string. One stamp, one answer, whichever way an
// operator asks.
func init() { web.Version = version }

const usage = `usage: kydns <command> [flags]

commands:
  serve     run the DNS and admin servers
  service   manage services
  record    manage records
  view      manage views
  token     manage API tokens
  blacklist manage domain filtering
  settings  view or change server settings
  dhcp      show DHCP server state and current leases
  replica   manage replication and pairing
  export    write registry contents to YAML or JSON
  import    load registry contents from YAML or JSON
  backup-drill verify a sealed recovery capsule can be built
  export-capsule write a sealed recovery capsule
  deposit   deposit a sealed capsule with KyRecovery
  restore   restore a capsule using custodian shares from stdin
  admin     local recovery: reset-password
  version   print the version
`

func run(args []string, stdout io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stdout, usage)
		return 2
	}
	switch args[0] {
	case "serve":
		fs := flag.NewFlagSet("serve", flag.ContinueOnError)
		fs.SetOutput(stdout)
		cfg := fs.String("config", "/etc/kydns/kydns.yaml", "path to the config file")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if err := app.Serve(ctx, *cfg, nil); err != nil {
			fmt.Fprintln(os.Stderr, "kydns:", err)
			return 1
		}
		return 0
	case "admin":
		// flag.Parse stops at the first positional, so take the subcommand
		// before parsing the flags that follow it.
		if len(args) < 2 || args[1] != "reset-password" {
			fmt.Fprintln(stdout, "usage: kydns admin reset-password [--config path]")
			return 2
		}
		fs := flag.NewFlagSet("admin reset-password", flag.ContinueOnError)
		fs.SetOutput(stdout)
		cfg := fs.String("config", "/etc/kydns/kydns.yaml", "path to the config file")
		if err := fs.Parse(args[2:]); err != nil {
			return 2
		}
		if err := app.ResetAdminPassword(*cfg, app.TerminalPassword, stdout); err != nil {
			fmt.Fprintln(os.Stderr, "kydns:", err)
			return 1
		}
		return 0
	case "version":
		fmt.Fprintln(stdout, version)
		return 0
	case "restore":
		fs := flag.NewFlagSet("restore", flag.ContinueOnError)
		fs.SetOutput(stdout)
		capsulePath := fs.String("capsule", "", "sealed capsule path")
		out := fs.String("out", "", "empty restore directory")
		if err := fs.Parse(args[1:]); err != nil || *capsulePath == "" || *out == "" || fs.NArg() > 0 {
			fmt.Fprintln(stdout, "usage: kydns restore --capsule path --out directory")
			fmt.Fprintln(stdout, "custodian shares are read from stdin, one per line")
			return 2
		}
		// capsule.Open refuses a non-empty target too, but only after the
		// custodians have read their cards aloud. Refuse before that.
		if entries, err := os.ReadDir(*out); err == nil && len(entries) > 0 {
			fmt.Fprintln(os.Stderr, "kydns: restore directory must be empty")
			return 1
		}
		raw, err := os.ReadFile(*capsulePath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "kydns:", err)
			return 1
		}
		var shares []shamir.Share
		scan := bufio.NewScanner(os.Stdin)
		for scan.Scan() {
			line := strings.TrimSpace(scan.Text())
			if line == "" {
				continue
			}
			share, err := shamir.ParseShare(line)
			if err != nil {
				fmt.Fprintln(os.Stderr, "kydns:", err)
				return 1
			}
			shares = append(shares, share)
		}
		if err := scan.Err(); err != nil {
			fmt.Fprintln(os.Stderr, "kydns:", err)
			return 1
		}
		key, err := recoverykey.Combine(shares)
		if err == nil {
			_, _, err = capsule.Open(raw, key, *out)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "kydns:", err)
			return 1
		}
		fmt.Fprintln(stdout, *out)
		return 0
	default:
		// Asking the cli package rather than repeating its command list here:
		// the list was duplicated once and the copies drifted.
		if cli.Lookup(args[0]) != nil {
			return cli.Run(args, stdout, os.Stderr)
		}
		fmt.Fprintf(stdout, "kydns: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}

func main() { os.Exit(run(os.Args[1:], os.Stdout)) }
