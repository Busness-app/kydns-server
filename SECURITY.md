# Security Policy

KyDNS is a self-hosted local DNS and service directory. Operators are
responsible for securing the host, network, credentials, and peer enrollment.

## Reporting vulnerabilities

Do not disclose suspected vulnerabilities in a public issue. Report them
privately to the project maintainer with the affected document or component,
impact, reproduction steps, and any suggested mitigation.

## Trust boundaries

- DNS clients are untrusted input and must not be able to change records.
- Administrative endpoints require authentication and authorization.
- A replication peer is trusted only after explicit operator enrollment.
- Discovery sources such as DHCP and Docker are configuration inputs and must
  be validated before their data is published.
- Remote blacklist sources are untrusted input and must be bounded, parsed, and
  atomically applied; they must never override authoritative local records.
- The local registry contains private service names and addresses.
- Query history is sensitive operational data and is not replicated by default.

## Required protections

- Encrypt and mutually authenticate replication connections.
- Validate domain names, record types, addresses, aliases, and peer IDs.
- Make replication changes idempotent and safe to retry.
- Record administrative, peer, replication, and conflict events without
  logging credentials, private keys, raw request bodies, or sensitive answers.
- Keep upstream credentials and private keys out of YAML and JSON exports.
- Keep public DNS names separate from private service names by default.
- Bind administrative services only to intended interfaces and protect them
  with the operator's network controls or a trusted TLS-terminating proxy.
- Fetch blacklist sources only over verified HTTPS, without sending query or
  client identity data to list providers.

## Known limitations

KyDNS is currently a product definition; implementation security has not yet
been verified. The replication design permits concurrent writers and uses
deterministic last-write-wins conflict resolution. Operators must monitor
replication failures and review conflicts before relying on synchronized data.

See [DESGINE.md](DESGINE.md) for the proposed architecture and
[LOGGING.md](LOGGING.md) for privacy-safe logging requirements.
