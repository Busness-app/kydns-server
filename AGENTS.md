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

This repository is currently documentation-only. Keep these documents aligned:

- `README.md` — product scope and user-facing capabilities.
- `DESGINE.md` — architecture and replication design.
- `LOGGING.md` — logging and privacy requirements.
- `SECURITY.md` — security policy and trust boundaries.
- `CONTRIBUTING.md` — contribution and verification workflow.
- `docs/superpowers/specs/2026-08-11-kydns-v1-design.md` — approved v1 design.
  Single-node; replication deferred to a later spec.

