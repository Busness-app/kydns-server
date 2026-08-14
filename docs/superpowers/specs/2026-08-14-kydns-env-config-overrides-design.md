# Environment overrides for the file-owned settings

Status: approved — not yet implemented
Date: 2026-08-14

Five settings are owned by the config file: `data_dir`, `dns.listen`,
`admin.listen`, `replication.listen`, and `replication.primary`. KyDNS needs
them before it has a database or a web UI, so they are read at every start and
changing one means a restart. Everything else in the file seeds a fresh
database once and is ignored afterwards.

This design lets those five, and only those five, also be set from the
environment.

## Why this decision exists

Getting a config file into a container is the friction, not the setting.

The image bakes a working `/etc/kydns/kydns.yaml` and runs on a distroless base
with no shell, so the file cannot be edited in place. Replacing it means a bind
mount, and a bind mount of a single *file* is the fragile kind: if the host
path does not exist first, Docker creates a directory there and the container
fails to start. On unRAID that is a terminal session, a `touch`, a path mapping
added by hand, and appdata permissions to get right — all to set one address on
a server that is otherwise administered entirely through a web UI.

A node already running happily makes this worse, because the mounted file
replaces the baked one wholesale. It must therefore carry `data_dir` and
`admin.listen` as well, and getting `data_dir` wrong points the node at a new
empty database instead of the operator's.

An environment variable is one field in the unRAID template, typed in a form,
with no file to create, no permissions to reason about, and no chance of
pointing the node at the wrong database. Applying the template restarts the
container, so the setting and the restart it requires are one action rather
than two.

Two alternatives were considered and rejected. A drop-in file that KyDNS writes
into `data_dir` when missing solves the same problem, but makes KyDNS a program
that writes configuration it also reads, leaves a generated template to go
stale once the operator owns it, mixes configuration into the volume that is
backed up and restored as a database, and still needs a second action to
restart. A `conf.d` directory under `/etc/kydns` avoids the file-versus-
directory trap but still requires a new path mapping, a hand-made file, and a
separate restart.

Environment configuration is already in the project's vocabulary: the CLI reads
`KYDNS_URL` and `KYDNS_TOKEN`.

## The surface

| Variable | Key |
|---|---|
| `KYDNS_DATA_DIR` | `data_dir` |
| `KYDNS_DNS_LISTEN` | `dns.listen` |
| `KYDNS_ADMIN_LISTEN` | `admin.listen` |
| `KYDNS_REPLICATION_LISTEN` | `replication.listen` |
| `KYDNS_REPLICATION_PRIMARY` | `replication.primary` |

The names are mechanical: `KYDNS_` followed by the YAML path with dots as
underscores, uppercased. Nothing needs to be memorised, and a sixth key added
to the file-owned set later has exactly one possible name.

The set stops at five on purpose. The rest of the file seeds a database on the
first run and is ignored on every start after it, so `KYDNS_DNS_TTL` would be a
knob that silently does nothing on every server that has been configured — the
precise confusion this feature exists to remove.

## Where it happens

`config.Load` gains one step between unmarshalling and defaults:

```
read file → unmarshal → domainProbe → overlayEnv → applyDefaults → validate
```

The position is load-bearing at both ends. Before `applyDefaults`, because
`admin.listen` is filled with `127.0.0.1:8053` only when empty, and an
environment value that arrived after it would lose to the default. Before
`validate`, because the values the process boots with are the ones that must be
checked: an address from the environment gets the same parsing, and the same
mutual-exclusion rule, as an address from the file. No validation is duplicated
and none is bypassed.

`overlayEnv` walks a table of `{envKey, *string}` pairs. It takes a
`getenv func(string) string` so tests supply their own environment.

## Precedence, and the empty case

The environment wins over the file. A variable that is set replaces whatever
the file said for that key.

**Empty means unset.** A variable set to the empty string is skipped, not
treated as an explicit clear. unRAID templates routinely carry variables whose
value has been left blank; were blank to mean "clear", a template shipping an
unused `KYDNS_REPLICATION_LISTEN` field would silently demote a working primary
to standalone, with a DNS server that still answers and replicas that quietly
stop syncing. Turning replication off stays what it is today: remove the key
from the file. The cost is that a file key cannot be unset from the
environment, which nothing needs.

## Mutual exclusion across sources

`replication.listen` and `replication.primary` together is a startup error
today, and stays one when the two values arrive from different places. A node
is a primary, a replica, or standalone; two sources disagreeing is not a
tiebreak KyDNS gets to invent.

The existing message names two keys, which would send an operator grepping a
YAML file that contains only one of them. It gains source attribution:

> `replication.listen (from the config file) and replication.primary (from
> KYDNS_REPLICATION_PRIMARY) are mutually exclusive: a node is a primary or a
> replica, never both`

## Observability

`Config` records which environment keys it applied and exposes them to callers,
so `app.Serve` can log one line naming them at startup. A variable set once and forgotten otherwise contradicts the file
forever with nothing in the logs to say why the file is being ignored — the
same failure mode as a promoted node whose file still names a primary, which
already logs that the key is being ignored.

That recorded list is also what the mutual-exclusion message reads to attribute
its sources, so there is one piece of bookkeeping rather than two.

## Testing

`Load` passes `os.Getenv`; `overlayEnv` takes the function so it can be
exercised directly without touching the process environment. Tests that go
through `Load` use `t.Setenv`, which `internal/config/config_test.go` can do
because it uses no `t.Parallel`.

- Each of the five variables overrides the file value.
- An unset variable and an empty variable both leave the file value standing.
- `KYDNS_ADMIN_LISTEN` suppresses the `127.0.0.1:8053` default rather than
  losing to it.
- File `replication.listen` plus `KYDNS_REPLICATION_PRIMARY` fails, and the
  message names both sources.
- A malformed address from the environment fails validation exactly as one from
  the file does, for both a listen address and the dialled primary.
- In `internal/app`: `RoleFrom` reports primary when only the environment set
  `replication.listen`.

## Documentation

The "five of them are owned by this file" paragraph in `kydns.example.yaml`
gains the environment equivalents, as do the README's configuration and unRAID
sections and the comment block in `docker-compose.yml`.

`kydns.docker.yaml` and the `Dockerfile` are unchanged. The image needing no
rebuild to gain a setting is the point of the feature.

## Out of scope

Node identity, pairing, and promotion are untouched. `KYDNS_URL` and
`KYDNS_TOKEN` stay CLI-only and gain no server-side meaning.

No secret is ever read from the environment. These five are paths and
addresses, which `docker inspect` may show freely; a pairing code or a token
must not follow them, because the environment of a running container is
readable by anything that can talk to the Docker socket.
