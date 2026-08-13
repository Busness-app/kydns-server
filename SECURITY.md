# Security Policy

KyDNS is a self-hosted local DNS and service directory. Operators are
responsible for securing the host, network, and credentials.

## Reporting vulnerabilities

Do not disclose suspected vulnerabilities in a public issue. Report them
privately to the project maintainer with the affected document or component,
impact, reproduction steps, and any suggested mitigation.

## Trust boundaries

- DNS clients are untrusted input and must not be able to change records.
  Queries are answered only from the `allow_query` ranges; everything else gets
  `REFUSED`.
- Administrative endpoints require authentication and authorization.
- Upstream resolvers are reached over DNS-over-TLS or DNS-over-HTTPS with
  certificate verification always on. Plain `udp://` is per-upstream opt-in and
  clears the authenticated-data bit on anything it answers.
- Discovery sources such as DHCP and Docker are configuration inputs and must
  be validated before their data is published.
- Remote blacklist sources are untrusted input: fetched only over HTTPS with
  certificate verification, redirects followed only while they stay HTTPS, a
  32 MB response body ceiling, a ceiling on parsed entries per list, no code
  execution of list contents, and applied atomically; they must never
  override authoritative local records. Only an authenticated administrator
  can change blacklist policy (lists, rules, and the filtering toggle).
- The local registry contains private service names and addresses. It also
  holds the admin password hash and API tokens, so write access to the database
  file is equivalent to administrative access.
- Query history is sensitive operational data. Query logging is off by default,
  and logging client IPs is a separate opt-in.
- Server settings live in the database and are changed only by an authenticated
  administrator, through the web UI, `PATCH /api/v1/settings`, or
  `kydns settings set`. All three go through one validation and write path, and
  a change either validates, persists, and applies in full or does none of
  those. The config file seeds those settings on the first run and is ignored
  afterwards, so a file an attacker edits on a running install changes nothing.

## Required protections

- Validate domain names, record types, addresses, and aliases.
- Record administrative events without logging credentials, private keys, raw
  request bodies, or sensitive answers.
- Keep upstream credentials and private keys out of YAML and JSON exports.
- Keep public DNS names separate from private service names by default.
- Bind administrative services only to intended interfaces and protect them
  with the operator's network controls or a trusted TLS-terminating proxy.
- Fetch blacklist sources only over verified HTTPS, without sending query or
  client identity data to list providers. Send a fixed `User-Agent: kydns`
  header and no other identifying headers.

## The `allow_query` guardrail

`allow_query` is the list of ranges KyDNS answers at all; everything else gets
`REFUSED`. Widening it past the operator's own network is the one settings
change that can turn a homelab resolver into an open resolver, so it is the one
change that is not a single click.

**What counts as private.** A prefix is private when it sits wholly inside
loopback (`127.0.0.0/8`, `::1/128`), RFC1918 (`10.0.0.0/8`, `172.16.0.0/12`,
`192.168.0.0/16`), ULA (`fc00::/7`), link-local (`169.254.0.0/16`, `fe80::/10`),
or CGNAT (`100.64.0.0/10`, which is what Tailscale uses). Containment, not
overlap: `0.0.0.0/0` overlaps every one of those ranges without being any of
them, and is public.

**Adding a public prefix takes a confirmation.** The exact canonical, masked
form of the prefix has to be retyped in the same request — the confirmation box
in the settings form, `confirm_public` on `PATCH /api/v1/settings`, or
`--confirm-public` on `kydns settings set`. Canonical form is the point: an
entry written as `192.168.1.99/0` behaves as `0.0.0.0/0` while reading as a LAN
address, so the operator confirms what the prefix actually matches, not what it
looks like. The confirmation is never derived from the value being saved, is
never stored, and is never returned.

**Only new exposure is confirmed.** A public prefix already stored counts as
already accepted, so changing an unrelated setting, or narrowing the list, never
asks again. Removing a prefix and re-adding it does ask, because by then it is
no longer in the stored list.

**Exposure stays visible.** For as long as any public prefix is configured, the
dashboard and the Settings screen carry a standing banner naming it, and KyDNS
logs a warning naming it at every start. Neither can be dismissed; removing the
prefix is what clears them.

**A public prefix in an existing config file is grandfathered.** Upgrading a
deployment whose `kydns.yaml` already sets a public `allow_query` seeds that
value and starts. It is not refused. Refusing to start would take a working
household's DNS offline over a file that was legal when it was written, which
trades a real outage for a risk the operator already chose to run. The warning
and the banner are what keep that choice visible instead of silent.

**Import cannot introduce one.** There is no place to type a confirmation in an
import document, so a document whose `allow_query` carries a public prefix the
server is not already serving is refused. In replace mode that check runs before
the destructive replacement, so a rejected import leaves the existing registry
and settings exactly as they were. Restore the backup without the prefix, then
add it with a confirmation.

## Known limitations

- **KyDNS is not a validating resolver.** It does not verify DNSSEC signatures,
  hold a trust anchor, or walk a chain of trust. An `AD` bit from KyDNS means
  the upstream said it validated, not that KyDNS checked.
- **The admin listener speaks plain HTTP.** It defaults to `127.0.0.1:8053`.
  Exposing it beyond loopback requires a TLS-terminating reverse proxy.
- **Blacklist filtering is domain filtering**, not traffic inspection, parental
  control, or a malware guarantee.
- Anyone with write access to the database file can reset the admin password
  with `kydns admin reset-password`. They can already read every hash and token
  in that file, so this adds no exposure — but the file is the trust boundary.

## Deferred: replication

Linked-server replication is designed but not implemented. Before it ships it
must encrypt and mutually authenticate peer connections, trust a peer only
after explicit operator enrollment, make changes idempotent and safe to retry,
and keep query history out of replication by default. The design permits
concurrent writers with deterministic last-write-wins conflict resolution, so
it must also surface failures and conflicts to the operator.

See [DESGINE.md](DESGINE.md) for the architecture and
[LOGGING.md](LOGGING.md) for privacy-safe logging requirements.
