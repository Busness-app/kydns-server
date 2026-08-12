# KyDNS Wildcard Records

Date: 2026-08-12
Status: **Deferred.** Designed, not scheduled. Superseded for the immediate use
case by [service proxy routing](2026-08-12-kydns-service-proxy-routing.md).

## Why this is deferred rather than dropped

The motivating case was a reverse proxy: `*.apps.urlxl.us` answering with the
proxy's address so a new application needs no DNS change. Service proxy routing
serves that better, because a wildcard gives naming and nothing else. Health
monitoring, correct reverse records and an inventory of what exists all require
the service to be registered, so a wildcard is an escape hatch out of the
product's entire value. It also makes every typo resolve: `gti.urlxl.us`
returns a confusing 502 from a proxy instead of a clean NXDOMAIN.

What would revive it: deploying applications often enough that registering each
one is real friction. Weekly is fine and the CLI covers it. Daily and scripted,
a wildcard starts earning its keep.

The design below is complete. It is recorded so the reasoning survives.

## Decisions

| Decision | Choice |
|---|---|
| What carries a wildcard | Manual records only — never services, aliases, leases or PTRs |
| Matching | Strict RFC 4592 closest-encloser |
| Zone-root wildcards | Allowed, but flagged in the UI |
| Observability | A wildcard-matched answer logs `source=wildcard` |

## Scope

A wildcard is a manual record whose leftmost label is `*`. `ValidateName`
(`internal/registry/validate.go:58`) currently rejects any `*`
(`wildcard_unsupported`); it would instead permit one only as the leftmost
label, per RFC 1034 §4.3.3. `*.apps.urlxl.us` valid; `apps.*.urlxl.us` and
`x*.urlxl.us` not. A, AAAA and CNAME may all be wildcards, subject to the
existing CNAME-coexistence check. Wildcards never derive reverse records.

Services stay concrete. A wildcard service would need a reverse record for a
name that does not exist, and aliases that compound meaninglessly.

## The node set

`zone.Index` gains a field:

```go
nodes map[string]bool // every name that exists, including empty intermediates
```

Built once per view after `Forward` is complete: insert each key and every
ancestor up to the zone apex. `*.apps.urlxl.us` therefore makes
`apps.urlxl.us` exist as an empty non-terminal, which is what lets the
closest-encloser walk terminate correctly. Costs nothing at query time.

## Lookup

`Authoritative.Answer` gains a fallback after an exact-match miss: walk up from
the queried name's parent to the first name present in `nodes` — the closest
encloser — then look up `"*." + that name`.

The synthesized records must carry the **queried** name as owner, not
`*.apps.urlxl.us`. RFC 4592 §3.3.1. A client handed a literal `*` owner rejects
the answer.

| Zone contains | Query | Result |
|---|---|---|
| `*.apps` | `x.apps` | wildcard |
| `*.apps` | `a.b.apps` | wildcard — nothing exists between |
| `*.apps` | `apps` | NODATA — a wildcard never matches its own parent |
| `*.apps`, `git.apps` | `git.apps` | `git.apps`; exact always wins |
| `*.urlxl.us`, `nas` | `backup.nas` | NXDOMAIN — `nas` is the closest encloser |
| `*.apps` (A only) | `x.apps` AAAA | NODATA — name matches, type does not |

## Views and precedence need no new machinery

`pick()` already resolves view-tagged over untagged, and a wildcard is a record
with a `View`, so per-view wildcards work with no extra code. Multi-homed
wildcards accumulate through the existing `claimed` logic.

Specificity beats layer precedence automatically: exact names and `*.` names
occupy different map keys and the exact lookup runs first, so a DHCP lease at
`laptop.urlxl.us` still beats a manual `*.urlxl.us` despite manual records
being the higher layer.

## Visibility

The Records screen badges any wildcard, and badges a zone-root one distinctly,
with a line saying it catches every unregistered name in the zone and
suppresses NXDOMAIN. With `log_queries` on, a wildcard-matched answer logs
`source=wildcard` rather than `source=authoritative`, which is the difference
between answering "why did this resolve?" in seconds and guessing.

## Out of scope

DNSSEC-signed wildcards (KyDNS does not sign), wildcard reverse records, and
wildcard services.
