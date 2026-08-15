package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/yoshiofthewire/kydns-server/internal/app"
	"github.com/yoshiofthewire/kydns-server/internal/cli"
	"github.com/yoshiofthewire/kydns-server/internal/web"
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
  replica   manage replication and pairing
  export    write registry contents to YAML or JSON
  import    load registry contents from YAML or JSON
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
