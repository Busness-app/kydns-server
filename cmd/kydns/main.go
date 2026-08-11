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
)

const usage = `usage: kydns <command> [flags]

commands:
  serve     run the DNS and admin servers
  service   manage services
  record    manage records
  view      manage views
  token     manage API tokens
  export    write registry contents to YAML or JSON
  import    load registry contents from YAML or JSON
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
	case "service", "record", "view", "token", "export", "import":
		return cli.Run(args, stdout, os.Stderr)
	default:
		fmt.Fprintf(stdout, "kydns: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}

func main() { os.Exit(run(os.Args[1:], os.Stdout)) }
