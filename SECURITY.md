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
