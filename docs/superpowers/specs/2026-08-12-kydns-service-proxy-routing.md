# KyDNS Service Proxy Routing

Date: 2026-08-12
Status: Approved, ready for implementation planning

## Scope

A service runs on plain HTTP somewhere on the LAN. A reverse proxy fronts it
with a real certificate. Clients should reach the proxy; monitoring should
reach the service. Today KyDNS forces a choice between the two, because the
address that answers DNS is also the address the reverse record derives from
and the only address the Services screen records.

This adds two fields to a service so DNS can answer with the proxy while
everything else keeps tracking the real thing.

Out of scope: wildcard records, which cover the same ground for unregistered
names and are deferred to
[their own spec](2026-08-12-kydns-wildcard-records-deferred.md). Also out of
scope: per-view proxying, proxy configuration generation, and certificate
issuance.

### Decisions

| Decision | Choice |
|---|---|
| Where the proxy lives | Per service, not per address |
| Fields | `ProxyAddress string` plus `RouteViaProxy bool` |
| Forward records | Proxy address when routed, real addresses otherwise |
| Reverse records | **Always** the real addresses, never the proxy |
| Aliases | Follow the same decision as the primary name |
| View selection | Runs first, on the real addresses |
| Health checks | Unchanged; still a free-form URL |

## Part 1 — Model

`store.Service` (`internal/store/model.go:17`) gains:

```go
ProxyAddress  string // optional; an IP, validated like Addresses
RouteViaProxy bool   // when true, forward records answer with ProxyAddress
```

The boolean is deliberately separate from the address. Turning routing off
without discarding the value is how an operator answers "is this the proxy or
the application?" — the single most common question when a proxied service
misbehaves. The cost is one invalid combination, which validation rejects:
`RouteViaProxy` true with an empty `ProxyAddress`.

`ProxyAddress` is validated by the existing `ValidateAddress`
(`internal/registry/validate.go:84`). It is an IP address, not a name, for the
same reason service addresses are.

The `services` table (`internal/store/store.go:39`) gains two columns with
defaults, so existing rows migrate without intervention:

```sql
proxy_address   TEXT NOT NULL DEFAULT '',
route_via_proxy INTEGER NOT NULL DEFAULT 0
```

## Part 2 — Forward and reverse stop sharing a source

This is the whole feature. In `buildIndex`
(`internal/zone/snapshot.go:106-131`) the service loop currently derives both
the forward and the reverse records from one slice of addresses. It splits:

- **Forward** records — the primary name and every alias — use the proxy
  address when `RouteViaProxy` is set, and the real addresses otherwise.
- **Reverse** records always derive from the real addresses.

View selection is unaffected and still runs first: `pick()` resolves which
real addresses apply to the view being built, and only then does routing decide
what the forward records answer with. A proxied service therefore answers with
the same proxy address in every view — the accepted consequence of a per-service
rather than per-address proxy — while its PTR still tracks whichever real
address that view selected.

Routing does not resurrect a service in a view it is absent from. When `pick()`
returns no addresses for a view, the service produces no records there, proxied
or not: a service with only a tailnet-tagged address stays invisible on the LAN.
The proxy decides what an existing answer says, never whether one exists.

Note that aliases are **address records, not CNAMEs**
(`internal/zone/snapshot.go:117-124` copies the address records to each alias
name). They follow the routing decision along with the primary name.

### The reverse-record collision this fixes

`internal/zone/snapshot.go:128` assigns `idx.Reverse[arpaName(addr)] = primary`
unconditionally. Ten services pointed at one proxy address today means ten
writes to one reverse key, and the last one silently wins. Deriving reverse
records from the real addresses removes that entirely for the proxy case,
because each service's real address is its own.

## Part 3 — The collision that remains

Two services that genuinely share an address still contend for its reverse
record, and the last writer still wins silently. That is a defect today,
independent of proxying, and it is in scope here because this is the code being
touched.

The fix is minimal rather than clever: when a reverse entry is about to be
overwritten by a **different** name, log a warning naming the address and both
names. Resolution stays last-writer-wins — picking a winner would be inventing
policy — but the operator can now find out why a reverse lookup returns
something unexpected. Silently wrong is the only outcome ruled out.

## Part 4 — Surfaces

**Services screen.** The add-service form gains "Proxy address" and a "Send DNS
to the proxy" checkbox. The services table shows `→ 192.168.1.20` on routed
rows, so an indirection that changes what every client resolves is visible on
the list rather than buried behind an edit.

**Health check copy.** The field is unchanged — it is already a free-form URL
independent of the service's addresses, which is what makes this work at all.
Only the help text changes, to say that the check should target the service
directly rather than the proxy: a proxy returning 502 for a dead backend still
looks healthy to a prober, which is the failure this whole feature is meant to
make visible.

**`check_insecure` gets a checkbox.** It exists in the model
(`internal/store/model.go:23`), the API (`internal/adminapi/api.go:54`) and the
CLI, but has no control in the web form, so a service with a self-signed
certificate sits permanently `down` with no way to fix it from a browser. The
same form is being edited; it goes in.

**API and CLI.** `serviceDTO` (`internal/adminapi/api.go:48`) gains
`proxy_address` and `route_via_proxy`, which puts them in `GET`/`POST`/`PATCH
/api/v1/services` and in export and import. The CLI gains `--proxy` and
`--via-proxy` on `kydns service add`.

## Part 5 — Tests

- A routed service's forward records answer with the proxy address; an unrouted
  one answers with its real addresses.
- Aliases follow the routing decision.
- **The reverse record derives from the real address even when routed** — the
  property the feature exists for.
- A proxied service answers identically in every view, while its reverse record
  still tracks the view-selected real address.
- Validation rejects `RouteViaProxy` with no proxy address, and a proxy address
  that is not an IP.
- Two services sharing one real address log the reverse-record conflict, naming
  both.
- Export and import round-trip both fields.
- The web form round-trips both fields and `check_insecure`.

## Part 6 — Documentation

The README's service description explains the pattern in one short section:
register the service at its real address, set the proxy address, tick the box,
and point the health check at the service rather than the proxy. It also
corrects the standing implication that aliases are CNAMEs — they are address
records.
