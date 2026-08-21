# Settings in the web UI

Status: approved
Date: 2026-08-13

## Why

KyDNS now runs as an Unraid container. Every setting lives in
`kydns.yaml`, which is read once at startup, so changing an upstream or a
TTL means opening a shell into a container, editing a file, and
restarting. The `/settings` page shows those values read-only next to a
note telling the operator to go do exactly that.

This moves every setting that can move into the database, edited from the
web UI, the JSON API, and the CLI. What stays in the file is only what
cannot be anywhere else.

## Scope

### Stays in `kydns.yaml`

| Key | Why it cannot move |
|---|---|
| `data_dir` | Holds the database that would store the setting. |
| `admin.listen` | Changing it changes the address of the page being used. |
| `dns.listen` | Bound before any UI is reachable; `:53` needs `CAP_NET_BIND_SERVICE`. |

In Unraid all three are the container template's job: one volume mapping
and two port mappings. The baked-in `kydns.docker.yaml` already sets
them, so an Unraid operator never edits YAML.

### Moves to the database

Applied live on save:

`upstreams`, `reverse_zones`, `allow_query`, `allow_tailscale`, `ttl`,
`cache_min_ttl`, `cache_max_ttl`, `negative_max_ttl`, `cache_entries`,
`log_queries`, `log_client_ip`, `health.interval`, `health.timeout`,
`health.workers`, `discovery.interval`, `discovery.dhcp_lease_file`

`discovery.dhcp_lease_file` moved to applied-live when the built-in DHCP
server landed: the poller's source became swappable, which is what both
features needed.

Requires a restart, and says so:

- `private_domain` — every zone snapshot, every FQDN, and the registry's
  name validation are built from it.

## Precedence: the database wins, the file seeds once

On startup, if the settings row is absent, the loaded YAML seeds it and
the row records that it was seeded. From then on the file's moved keys
are ignored.

The cost of this model is that editing YAML after the first boot does
nothing, silently. Both places must say so:

- `kydns.example.yaml` is rewritten. Each moved key is annotated as a
  first-run seed value with a pointer to the settings page.
- `/settings` names the three keys the file still owns, and says the
  rest were seeded from it on first run.

## Runtime: a settings holder

A new `internal/settings` package owns an immutable `Snapshot` behind an
`atomic.Pointer`, mirroring `policy.Holder` and `zone.Holder`. It is the
third instance of a pattern the codebase already uses twice.

Components grow narrow swap methods, each a single atomic pointer store:

- `dnsserver.ACL.Replace([]netip.Prefix)`
- `dnsserver.Forwarder.Replace([]upstream.Upstream)`
- `dnsserver.Cache.Retune(entries, min, max, negMax int)`
- `dnsserver.Server.SetLogging(queries, clientIP bool)`
- `health.Checker.Reconfigure(interval, timeout time.Duration, workers int)`
- `discovery.Poller.SetInterval(time.Duration)`
- `zone.Holder.Rebuild()` — already exists; covers `reverse_zones`

The DNS hot path stays lock-free: readers load a pointer, they never take
a mutex.

`internal/app` owns the single `apply(*settings.Snapshot)` that fans out.
It is the only place that knows the full set of components, which is what
that package is for.

Rejected alternatives:

- **Mutable `config.Config` behind an `RWMutex`.** Fewer new types, but
  it turns a value into shared mutable state and puts a read lock on
  every query.
- **A supervisor that rebuilds the DNS server on change.** Drops
  in-flight queries on every save, and rebinding `:53` can fail once
  privileges are dropped.

## Data model

One singleton table, following `blacklist_settings`:

```sql
CREATE TABLE IF NOT EXISTS settings (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  private_domain   TEXT NOT NULL,
  reverse_zones    TEXT NOT NULL,
  upstreams        TEXT NOT NULL,
  allow_query      TEXT NOT NULL,
  allow_tailscale  INTEGER NOT NULL,
  ttl              INTEGER NOT NULL,
  cache_min_ttl    INTEGER NOT NULL,
  cache_max_ttl    INTEGER NOT NULL,
  negative_max_ttl INTEGER NOT NULL,
  cache_entries    INTEGER NOT NULL,
  log_queries      INTEGER NOT NULL,
  log_client_ip    INTEGER NOT NULL,
  dhcp_lease_file  TEXT NOT NULL,
  discovery_interval INTEGER NOT NULL,
  health_interval  INTEGER NOT NULL,
  health_timeout   INTEGER NOT NULL,
  health_workers   INTEGER NOT NULL
);
```

Added as a `migrations` entry so existing databases pick it up on the
first start after upgrade.

`reverse_zones`, `upstreams`, and `allow_query` are newline-separated
TEXT. They are always read and written whole, ordering is positional, and
a `settings_list(kind, ord, value)` table would buy only joins. Marked
`ponytail:` in the code with the upgrade path: split into a table if
per-entry editing ever appears.

Reads and writes go through `store.Settings()` and
`store.PutSettings()`, keeping the store the single write chokepoint.

## Validation

`Config.validate` today runs only against YAML. Its body moves to
`settings.Validate(Settings) error`, and both the seed and the API write
call it. Nothing can reach the database that could not have been in the
file.

- every entry of `allow_query` and `reverse_zones` parses as a prefix
- `upstream.ParseAll` accepts every upstream
- `cache_min_ttl <= cache_max_ttl`
- `ttl`, `cache_entries`, and the TTL bounds are positive
- `health.workers >= 1`, `health.timeout < health.interval`
- `private_domain` is non-empty and is a valid domain name

`config.Load` keeps validating the three bootstrap keys it still owns.

## The allow_query guardrail

`allow_query` is what stops KyDNS being an open resolver, so the UI must
not let it be widened by accident.

A prefix is private if it is contained by loopback, RFC1918, ULA,
link-local, or CGNAT. `Validate` rejects any other prefix unless the same
request carries `confirm_public` set to the literal prefix being added —
retyping `0.0.0.0/0` in a second field on the form, or
`--confirm-public 0.0.0.0/0` on the CLI.

Retyping the prefix rather than ticking a box means the confirmation
cannot be muscle memory, and a copy-pasted API body cannot carry a
blanket override.

While a public prefix is active:

- a standing red banner on the dashboard and the settings page
- a warning logged at every start, naming the prefix

## Write path

1. Parse the request into a partial settings document.
2. Merge over the stored values.
3. `settings.Validate` — reject with a field-level error on failure.
4. `store.PutSettings` in one transaction.
5. `settings.Holder.Rebuild()`.
6. `app.apply(snapshot)`.

`apply` constructs everything that can fail before it swaps anything.
Building the new upstream set is the only fallible step; after it
succeeds, every swap is an infallible atomic store. All-or-nothing, the
same contract as `zone.Holder.Rebuild`. A rejected save leaves the
running configuration untouched and returns the error to the form.

## Restart-required banner

No dirty flag, which would drift out of sync with reality. The process
remembers the boot value of each restart-required key; the banner appears
whenever a stored value differs from the running one, names both, and clears
on restart because the comparison becomes equal.

Nothing produces it today. `dhcp_lease_file` was the last key that fed it and
it now applies live, so the comparison it ran is gone from the app. A
`private_domain` rename is caught earlier instead, by the two-step confirmation
on the settings page that lists the records it would move. The banner itself is
kept for the first key that needs it again.

## API and CLI

- `GET /api/v1/settings` — the effective settings as JSON.
- `PUT /api/v1/settings` — a **partial** document. Fields are pointers;
  absent keys are unchanged.

Partial PUT makes `kydns settings set ttl=120` a single request rather
than a read-modify-write that could clobber a concurrent edit from the
UI. The web form posts every field, so it is unaffected.

CLI: `kydns settings get` prints effective values; `kydns settings set
key=value ...` sends one partial PUT.

Settings join the export document in `snapshotDoc`, so a backup is
complete, and are accepted on import.

## Web UI

`/settings` gains an editable Server settings card above the existing
Views and API tokens cards, using the form patterns already in
`settings.html`. Grouped as DNS, Cache, Logging, Discovery, Health. Text
inputs for scalars, textareas for the three lists (one entry per line),
checkboxes for the two log toggles and `allow_tailscale`.

Each save posts to `/settings/server`, is CSRF-protected like every other
form on the page, and re-renders with a field-level error on rejection
rather than discarding the input.

The read-only `configRows` table shrinks to the three file-owned keys and
keeps its restart note, which is now accurate for exactly those keys.

The existing "view can never match" message on the Views card currently
tells the operator to edit the config file. It becomes a pointer to the
`allow_tailscale` checkbox on the same page.

## Testing

- `internal/settings`: validation table test, including every guardrail
  rejection and the `confirm_public` override.
- `internal/store`: round-trip of the settings row, list order preserved,
  migration applied to a database created before it existed.
- Component swaps: for each of `ACL.Replace`, `Forwarder.Replace`,
  `Cache.Retune`, `Server.SetLogging`, `Checker.Reconfigure`,
  `Poller.SetInterval`, a test that behaviour changes after the swap.
- Concurrency: `go test -race` with a swap running against live reads,
  asserting no torn state.
- `internal/app`: a failed `apply` leaves the previous configuration
  serving.
- Seeding: a fresh database seeds from YAML; a second start with a
  changed YAML does not overwrite the stored values.
- `internal/adminapi`: partial PUT leaves absent fields alone; a public
  prefix without confirmation is rejected; export and re-import
  round-trips settings.
- `internal/config/example_test.go` is updated for the reduced file and
  keeps asserting that `kydns.docker.yaml` loads and is safe.

## Documentation

`README.md`, `AGENTS.md`, `kydns.example.yaml`, `kydns.docker.yaml`, and
`SECURITY.md` (the `allow_query` guardrail and its override) are updated
in the same change. `DESGINE.md` gains the settings holder alongside the
zone and policy holders.
