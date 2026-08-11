# KyDNS

KyDNS is a planned self-hosted local DNS and service directory for homes,
homelabs, and small teams.

Its primary job is to make private services easy to name and reach. Ad and
tracker blocking is optional; local service discovery and DNS management are
the product.

## Example

Register a service once:

```sh
kydns service add kypost \
  --address 192.168.1.20 \
  --alias webmail \
  --check https://kypost.home.arpa/health
```

Clients can then use:

```text
kypost.home.arpa
webmail.home.arpa
```

without manually maintaining hosts files or opaque DNS rewrite rules.

## Planned capabilities

- First-class services, aliases, A, AAAA, CNAME, and reverse records.
- A configurable private domain such as `home.arpa`.
- DHCP lease and Docker Compose discovery.
- Separate views for home, VPN, guest, and lab networks.
- Health checks and service status in the web interface.
- Linked-server replication: authenticated KyDNS servers must synchronize
  configuration and service changes across the network, retrying updates when a
  peer is temporarily unavailable.
- YAML, JSON, and CLI import/export for backup and Git-based configuration.
- Optional local TLS certificates for private service names.
- Optional Pi-hole, AdGuard Home, and other filter-list integration.

## Security model

- DNS data stays on the operator's network.
- The server does not send query history to a KySecurity service.
- Administrative changes require authentication and are recorded locally.
- Configuration exports must not contain upstream credentials or private keys.
- Public DNS names and private service names remain separate by default.

See [DESGINE.md](DESGINE.md) for the architecture, [LOGGING.md](LOGGING.md)
for logging requirements, and [SECURITY.md](SECURITY.md) for security policy.

## Initial scope

The first version should provide a small DNS server, a service registry, and a
simple web UI. It should solve local naming well before adding ad blocking,
parental controls, device posture, or traffic inspection.

## Repository status

KyDNS is currently a product definition only. Implementation has not started.
