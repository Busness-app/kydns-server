# KyDNS Server

KyDNS is a Homelab DNS server with easy domain name assignments and blackhole filtering.

Please see the css directory and fonts directory for look and feel.

# Ponytail, lazy senior dev mode

Use the smallest correct change.

1. Reuse what already exists.
2. Prefer stdlib and native platform APIs.
3. Add dependencies only when they remove meaningful code.
4. Fix shared root causes, not one caller.
5. If a shortcut has a limit, mark it with `ponytail:` and name the upgrade path.

Non-trivial logic must include one runnable check (unit test or minimal self-check).

# DOX framework

## Core Contract

- AGENTS.md files are binding contracts for their subtree.
- Read from root to nearest AGENTS.md before editing.
- The nearest AGENTS.md controls local details; parent docs keep global rules.

## Update After Editing

- Run a DOX pass for every meaningful change.
- Update nearest owning AGENTS.md when behavior, responsibilities, or verification changes.
- Keep Child DOX Index entries current and delete stale rules.

## User Preferences

- Best-effort 90-second keyword refresh policy (foreground cadence; background catch-up on resume).
- DOX hierarchy scope is app-only.

## Child DOX Index

Keep these aligned:

- `README.md` — product scope and user-facing capabilities.
- `DESGINE.md` — architecture. Replication is designed but deferred.
- `LOGGING.md` — logging and privacy requirements.
- `SECURITY.md` — security policy and trust boundaries.
- `CONTRIBUTING.md` — contribution and verification workflow.
- `docs/superpowers/specs/2026-08-11-kydns-v1-design.md` — approved v1 design.
  Single-node with per-subnet views; replication deferred to a later spec.
- `docs/superpowers/specs/2026-08-12-kydns-blacklists.md` — approved DNS
  blackhole filtering design.
- `docs/superpowers/specs/2026-08-13-kydns-settings-in-the-ui-design.md` —
  approved design for settings in the database: what stays in the config file,
  what moves, what applies live, and the `allow_query` guardrail.
- `docs/superpowers/plans/2026-08-13-kydns-settings-in-the-ui.md` — the
  implementation plan for that spec.

Code, one concern per package:

- `cmd/kydns` — command dispatch. `serve`, `admin`, and the API-backed verbs.
- `internal/app` — process wiring: config, store, servers, background loops.
- `internal/config` — the YAML config and its defaults. The file owns three
  keys (`data_dir`, `dns.listen`, `admin.listen`); every other key it carries
  is a first-run seed for the database. `internal/config/example_test.go`
  asserts `kydns.example.yaml` against the defaults and against that split, so
  a key the file no longer controls cannot be documented as if it did.
- `internal/settings` — the settings snapshot the runtime reads, and the single
  path by which it changes: validate, persist, rebuild, apply, all or nothing.
- `internal/store` — SQLite schema and migrations, the single write chokepoint.
- `internal/registry`, `internal/zone` — services, records, views, validation,
  and the immutable zone snapshot the DNS server reads.
- `internal/dnsserver` — ACL, authoritative answers, cache, forwarding.
- `internal/upstream` — DoT, DoH, and opt-in plain-UDP upstreams.
- `internal/policy` — blacklist normalization, list parsing, fetch, refresh,
  and decision (deny/allow/list) for the DNS pipeline.
- `internal/discovery`, `internal/health` — DHCP leases and check probes.
  Runtime state only; never persisted unless an operator promotes it.
- `internal/adminapi`, `internal/web`, `internal/auth` — JSON API, server-side
  rendered UI, sessions and password hashing.
- `internal/cli` — the API client behind the non-`serve` commands.

The build must stay cgo-free: the image is distroless, so the pure-Go SQLite
driver is not optional.

