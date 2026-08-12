# Contributing to KyDNS

KyDNS is a Go server with a web UI and a CLI. Contributions should keep the
code and the product scope, design, security, and logging documents consistent.

## Before contributing

- Read [AGENTS.md](AGENTS.md) before editing.
- Read [SECURITY.md](SECURITY.md) before changing trust boundaries,
  replication, authentication, or data handling.
- Keep changes focused and avoid speculative implementation or dependencies.
- Update the owning documentation when behavior, responsibilities, or
  verification requirements change.

## Documentation changes

Use plain Markdown and link related requirements instead of duplicating them.
Keep `README.md`, `DESGINE.md`, `LOGGING.md`, and `SECURITY.md` aligned when a
change affects more than one concern. The blacklist behavior is owned by
[`docs/superpowers/specs/2026-08-12-kydns-blacklists.md`](docs/superpowers/specs/2026-08-12-kydns-blacklists.md).

## Verification

Every non-trivial logic change needs a runnable check in the same commit.

```sh
make test    # go test ./...
make build   # bin/kydns
```

CI additionally runs `gofmt -l`, `go vet`, a `go mod tidy` cleanliness check,
the tests under `-race`, a cgo-free build, and a Docker job that resolves a
local service name and a public name end to end. The build must stay cgo-free:
the image is distroless, so the pure-Go SQLite driver is not optional.

For documentation-only changes:

- check Markdown links and headings;
- search for stale project names or contradictory requirements;
- inspect the complete diff for unintended changes.

## AI-assisted contributions

Disclose AI assistance in the commit or pull request. State whether the work
was assisted, generated, or agentic, and record the checks a human performed.

## Code of conduct

All contributors must follow [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
