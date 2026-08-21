# Task 11: API and CLI surface — report

Branch `worktree-dhcp-part1`, from `3c3d51e`.

**Provenance.** I did not write this code. A previous implementer completed
it and was interrupted before writing a report or committing; it sat in the
working tree as an uncommitted diff plus four untracked files. This report is
a verification of that diff, not a first-person account of building it. The
implementing agent's session is gone, so there is no RED-first history to
show — no failing-test transcript was observed by me, and I am not
reconstructing one. Everything below is what I actually ran against the tree
as I found it, on 2026-08-21.

The brief (`task-11-brief.md`) predates five rulings and guesses wrong on
most identifiers — `GET /api/dhcp/leases`, dotted CLI keys (`dhcp.enabled`),
an exported `API.DHCP` field. The actual diff follows the rulings, not the
brief. I checked it against the rulings, not the brief's code samples.

## What the diff contains, file by file

| File | Status | Change |
| --- | --- | --- |
| `internal/adminapi/dhcp.go` | new | `WithDHCP(status func() (bool, error)) *API` setter for the unexported `dhcpStatus` field; `getDHCPStatus` handler. |
| `internal/adminapi/dhcp_test.go` | new | 8 tests (below). |
| `internal/adminapi/api.go` | modified | `dhcpStatus func() (bool, error)` field on `API`; route `GET /api/v1/dhcp/status` registered behind `auth(...)` beside `/api/v1/leases` and `/api/v1/leases/{ip}/promote`. |
| `internal/adminapi/settings.go` | modified | Seven `DHCP*` fields added to `settingsDTO` with both `json` and `yaml` tags; wired in both `toSettingsDTO` and `fromSettingsDTO`. |
| `internal/app/serve.go` | modified | One line: `.WithDHCP(dhcpRun.Status)` added to the `adminapi.API` builder chain. |
| `internal/cli/dhcp.go` | new | `dhcpCmd` with `status` and `leases` subcommands. |
| `internal/cli/dhcp_test.go` | new | 6 tests (below). |
| `internal/cli/cli.go` | modified | `{"dhcp", "show DHCP server state and current leases", dhcpCmd}` added to the `Commands` registry. |
| `internal/cli/settings.go` | modified | Seven snake_case keys added to `settingsUsage` and `settingsKinds`. |
| `internal/cli/settings_test.go` | modified | `TestSettingsSetDHCPKeys`, `TestSettingsUsageListsDHCPKeys` added. |
| `cmd/kydns/main.go` | modified | `dhcp` line added to the binary's usage text (out of brief; judged below). |
| `internal/web/serversettings.go` | modified | `postServerSettings` carries the seven DHCP fields forward from `liveSettings()` before saving (out of brief; judged below). |
| `internal/web/serversettings_test.go` | modified | `TestPostServerSettingsKeepsTheDHCPConfiguration` added. |
| `internal/web/templates/discovered.html` | modified | Off-state copy: "and restart KyDNS" → "it applies straight away" (out of brief; judged below). |
| `kydns.example.yaml` | modified | `dhcp_lease_file` comment corrected: no longer says "takes a restart". |

## How each ruling is satisfied

**R13 — one status endpoint, no parallel lease route.** `internal/adminapi/api.go:242`
registers only `GET /api/v1/dhcp/status`. There is no second lease-listing
route; `GET /api/v1/leases` (line 240, pre-existing) is untouched and still
serves both discovery and built-in leases through the same poller, per
Task 10. `getDHCPStatus` (`dhcp.go`) returns exactly `{"running":bool}` with
`error` added via `omitempty` only when non-empty — confirmed by reading the
struct literal, and by `TestDHCPStatusWithoutARunner` asserting `error` is
absent when nothing failed.

**R35 — builder, not exported field.** `WithDHCP(status func() (bool, error)) *API`
stores into the unexported `dhcpStatus` field (`api.go:36`) and returns `a`
for chaining, matching `WithSettings`/`WithMetrics`/`WithReplication` beside
it. `serve.go` calls `.WithDHCP(dhcpRun.Status)` in the same chain. A nil
`dhcpStatus` (every existing test that builds an API without calling
`WithDHCP`) reads `running: false`, no error — verified directly by
`TestDHCPStatusWithoutARunner`, and indirectly by every other adminapi test
in the suite continuing to pass unmodified.

**R32 — both tag sets, both directions.** `settings.go:39-48` (as read from
the diff) shows all seven fields with `json:"..." yaml:"..."` tags. Counted
against `toSettingsDTO`/`fromSettingsDTO`: both conversions list exactly the
same seven fields (`DHCPEnabled` through `DHCPSecondaryDNS`); neither is
missing one relative to the other or to the DTO. `TestSettingsExportImportRoundTripKeepsDHCP`
exercises this directly — it patches settings, exports, clears the fields
with a second patch, imports the export, and asserts all seven fields came
back. That test only passes because both the yaml tags and both conversion
directions are present; I did not need to fake a failure to trust it, but I
did trace the export path (`/api/v1/export`) to confirm it serializes via
`yaml.Marshal` on the DTO, which is exactly where a missing yaml tag would
have silently blanked the field, per the hazard the settings.go comment
documents at lines 34-37.

**R33 — snake_case CLI keys in both places.** `internal/cli/settings.go`:
the `settingsUsage` string lists `dhcp_enabled, dhcp_interface,
dhcp_range_start, dhcp_range_end, dhcp_gateway, dhcp_lease_seconds,
dhcp_secondary_dns`; `settingsKinds` has all seven with correct types
(`bool` for enabled, `int` for lease_seconds, `string` for the rest).
`TestSettingsUsageListsDHCPKeys` asserts every key appears in the usage
string. `TestSettingsSetDHCPKeys` asserts `kydns settings set
dhcp_enabled=true dhcp_interface=eth0 ...` produces a PUT body with the
right JSON types (bool `true`, number `3600`, not stringified).

**R34 — one `dhcp` command, `status` + `leases`, registered.** `cli.go:107`
adds `{"dhcp", ..., dhcpCmd}` to `Commands`. `dhcp.go`'s `dhcpCmd` dispatches
`status`/`leases`, printing usage and exiting 2 for anything else or no
args (`TestDHCPUnknownSubcommand`). `dhcpLeases` reads `/api/v1/leases` (not
a new endpoint), decodes `Expires int64` — matching `listLeases`'s
`"expires": l.Expires.Unix()` — and renders it with the existing `unixTime`
helper (`internal/cli/replica.go:436`), the same one three other commands
already use for Unix-second fields. When the list is empty it calls
`dhcpStatus` and prints "not running" / the error, so an operator is told
why rather than shown a blank — `TestDHCPLeasesEmptyExplainsWhy` and
`TestDHCPLeasesPrintsATable` (which also asserts the raw Unix integer never
appears in the output) both cover this.

**"takes a restart" comment** — `kydns.example.yaml`'s comment above
`dhcp_lease_file` now reads "edit it under Settings, where it applies
immediately", correcting the stale claim Task 10 made false.

## Judgement on the three out-of-brief changes

**1. `cmd/kydns/main.go` — add `dhcp` to the usage text.** Warranted, and
trivial. The `Commands` registry's own comment records that a command
implemented but not advertised in the binary's `--help` output has happened
twice before on this project. This is the one-line fix for exactly that
class of miss, applied proactively rather than after a third occurrence. No
test covers the usage string's content (none of the neighboring commands are
tested there either), but `TestDHCPCommandIsRegistered` in `cli/dhcp_test.go`
covers the actual reachability concern (`Lookup("dhcp") != nil`).

**2. `internal/web/serversettings.go` — carry DHCP fields through
`postServerSettings`.** I verified the claim directly rather than taking it
on faith. `postServerSettings` builds a fresh `store.Settings{}` struct
literal (line 81) populated only from named form fields, then an `intField`
loop for nine int fields, then calls `s.o.Settings.Set(v, confirm)` — a full
replace, not a merge. Before this diff, `v` never touched any `DHCP*` field,
so all seven would zero on every save from `/settings/server`: `DHCPEnabled`
false, every string cleared, `DHCPLeaseSeconds` 0. Since the web settings
form has no DHCP inputs yet (Part 2 territory), *any* save from that page —
renaming the private domain, changing an upstream, toggling `log_queries` —
would silently switch off a running built-in DHCP server on save. That is a
genuine Critical-class defect: DHCP silently disabling itself takes a LAN's
address assignment down with no operator action pointed at DHCP at all. The
fix (`liveSettings()` read-and-carry, seven lines) is the smallest closure of
the gap and is exactly what the DTO change exposed — it did not exist before
the DTO carried these fields at all. `TestPostServerSettingsKeepsTheDHCPConfiguration`
sets all seven fields, submits an unrelated valid save, and asserts they
survive. I re-read the test and the handler together; the claim holds.

**3. `internal/web/templates/discovered.html` — "and restart KyDNS" → "it
applies straight away".** Correct and appropriately scoped. Task 10 made the
lease-file swap live (`Apply` calls `poller.SetSource` at runtime); the old
"restart KyDNS" copy became false the moment that shipped, and this diff is
a one-line correction of stale UI copy, not new functionality. I confirmed
the diff touches only the trailing clause and leaves the sentence's other
claim — that setting `dhcp_lease_file` is the only way to turn discovery on
— completely untouched, which is the deferred item the task instructions
said must NOT be addressed here. It is not addressed; the diff has no other
change to this file.

## Gap check

- **`getDHCPStatus` behind auth, with a 401 test?** Yes.
  `api.go:242`: `auth(a.getDHCPStatus)`, same wrapper as every other route on
  that line range. `TestDHCPStatusRequiresAuth` asserts 401 with no token.
- **`fromSettingsDTO` carries all seven, matching `toSettingsDTO`?** Yes,
  counted directly: both list `DHCPEnabled, DHCPInterface, DHCPRangeStart,
  DHCPRangeEnd, DHCPGateway, DHCPLeaseSeconds, DHCPSecondaryDNS` — seven each,
  same names, no extra or missing field either direction.
- **Does `dhcp leases` render `expires` correctly given it's a Unix int?**
  Yes. `internal/adminapi/api.go:824` sends `l.Expires.Unix()` (an int64
  number in JSON); `cli/dhcp.go` decodes it into `Expires int64` and renders
  with `unixTime(l.Expires)`. `TestDHCPLeasesPrintsATable` asserts the
  RFC3339 rendering appears and the raw integer does not.
- **Does anything touch `internal/store`?** No. `git diff --stat` for this
  working tree lists no file under `internal/store/`. The seven `DHCP*`
  fields on `store.Settings` (`internal/store/model.go:109-115`) and their
  trigger/scan wiring (`internal/store/settings.go`, `internal/store/store.go`)
  already existed from earlier tasks in this series (visible via `git blame`
  as prior commits, not this diff) and are read-only from this task's
  perspective. No `dhcp_*` column was added to `cv_settings_u`, and no `cv_`
  trigger was added to any lease table.
- **Does any test open a real socket?** No. Both new test files use
  `httptest.NewServer`/`httptest.NewRequest` (loopback-only Go test
  infrastructure, not raw sockets), and neither touches `dhcpd` package
  internals that would bind port 67/68. `grep -n "net.Listen"` against both
  new test files returns nothing.

No gap was found that needed closing. I added nothing beyond what was
already in the working tree.

## Commands run and their output

```
$ go build ./...
(clean, no output)

$ go test ./internal/adminapi/... ./internal/cli/... ./internal/web/... -count=1
ok  	github.com/yoshiofthewire/kydns-server/internal/adminapi	0.301s
ok  	github.com/yoshiofthewire/kydns-server/internal/cli	0.019s
ok  	github.com/yoshiofthewire/kydns-server/internal/web	14.278s

$ go test ./... -count=1
ok  	github.com/yoshiofthewire/kydns-server/cmd/kydns	0.005s
ok  	github.com/yoshiofthewire/kydns-server/internal/adminapi	0.249s
ok  	github.com/yoshiofthewire/kydns-server/internal/app	24.428s
ok  	github.com/yoshiofthewire/kydns-server/internal/auth	0.551s
ok  	github.com/yoshiofthewire/kydns-server/internal/cli	0.034s
ok  	github.com/yoshiofthewire/kydns-server/internal/config	0.013s
ok  	github.com/yoshiofthewire/kydns-server/internal/dhcpd	0.008s
ok  	github.com/yoshiofthewire/kydns-server/internal/discovery	0.362s
ok  	github.com/yoshiofthewire/kydns-server/internal/discovery/dhcp	0.003s
ok  	github.com/yoshiofthewire/kydns-server/internal/dnsserver	0.176s
ok  	github.com/yoshiofthewire/kydns-server/internal/health	0.236s
ok  	github.com/yoshiofthewire/kydns-server/internal/policy	0.176s
ok  	github.com/yoshiofthewire/kydns-server/internal/registry	0.056s
ok  	github.com/yoshiofthewire/kydns-server/internal/replica	0.259s
ok  	github.com/yoshiofthewire/kydns-server/internal/settings	0.007s
ok  	github.com/yoshiofthewire/kydns-server/internal/store	0.257s
ok  	github.com/yoshiofthewire/kydns-server/internal/upstream	0.135s
ok  	github.com/yoshiofthewire/kydns-server/internal/web	13.358s
ok  	github.com/yoshiofthewire/kydns-server/internal/zone	0.005s

(19 packages, 0 failures)

$ go vet ./...
(clean, no output)

$ gofmt -l internal/
(no output)
```

## Test inventory (new)

`internal/adminapi/dhcp_test.go` (8): `TestSettingsJSONCarriesDHCPFields`,
`TestPatchSettingsAppliesDHCPFields`, `TestSettingsExportImportRoundTripKeepsDHCP`,
`TestDHCPStatusWithoutARunner`, `TestDHCPStatusRunning`,
`TestDHCPStatusReportsWhyItIsNotRunning`, `TestDHCPStatusRequiresAuth`,
`TestDHCPSettingsRejectedOnAReplica`.

`internal/cli/dhcp_test.go` (6): `TestDHCPCommandIsRegistered`,
`TestDHCPStatusPrintsTheReason`, `TestDHCPStatusRunning`,
`TestDHCPLeasesPrintsATable`, `TestDHCPLeasesEmptyExplainsWhy`,
`TestDHCPUnknownSubcommand`.

Plus `TestSettingsSetDHCPKeys` and `TestSettingsUsageListsDHCPKeys` in
`internal/cli/settings_test.go`, and `TestPostServerSettingsKeepsTheDHCPConfiguration`
in `internal/web/serversettings_test.go`.

## Concerns

- **No RED-first evidence.** I cannot show the implementing agent's failing
  tests because that session was lost. Everything I verified is
  post-hoc: I read the diff, cross-checked it against the five rulings and
  the brief's original intent, and ran the full suite green. That is real
  verification, but it is not the same as having watched the tests fail
  first. Anyone auditing this for TDD discipline should treat that history
  as genuinely unavailable, not merely unreported.
- **The web-settings fix (item 2 above) is the only substantive judgment
  call in this report.** I traced the handler and the DTO change myself
  rather than trusting the diff's own comment, and I believe the defect is
  real and the fix is correctly scoped (touches only the DHCP fields, no
  restructuring of the handler). A reviewer should still re-check this one,
  since it's the one place this diff reaches outside the brief's named files
  for a correctness reason rather than a naming one.
- Everything else — CLI key names, route registration, tag pairs, the
  builder pattern — matches the rulings exactly as specified, with no
  judgment calls needed on my part.
