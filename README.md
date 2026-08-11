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

## What works today

- First-class services, aliases, A, AAAA, CNAME, and derived reverse records.
- A configurable private domain, `home.arpa` by default.
- Per-subnet views: one name can answer differently on the LAN and over a VPN.
- DHCP lease discovery from dnsmasq, with promote-to-service.
- Health checks over HTTP, HTTPS, and TCP, with status in the web interface.
- Upstream forwarding with a cache, sequential failover, and single-flight.
- A web UI, a JSON API, and a CLI that talks to the API.
- YAML and JSON import/export for backup and Git-based configuration.

## Not yet

- **Ad and tracker blocking, and filter lists.** There is no blocklist support
  of any kind. Local naming came first, deliberately.
- Linked-server replication between KyDNS peers. The store keeps a single write
  chokepoint so the change log can be added without restructuring.
- DNS-over-TLS and DNS-over-HTTPS to upstreams. Plain UDP and TCP only.
- Docker Compose discovery, and lease formats other than dnsmasq.
- Local TLS certificate issuance for private service names.

## Configuration

Copy [`kydns.example.yaml`](kydns.example.yaml) to `/etc/kydns/kydns.yaml`, or
point somewhere else with `--config`. Every setting has a default, so a file
containing only `data_dir` is valid.

The config file is read once at startup: **changing it requires a restart.**
Services, records, views, and API tokens are not in it — they live in the
database and are edited through the web UI or the CLI. The Settings screen
shows the loaded config read-only, so you can see what the running server
actually has.

| Setting | Default | Notes |
|---|---|---|
| `data_dir` | *required* | Holds the database and the bootstrap/setup tokens. Back it up. |
| `dns.listen` | `:53` | UDP and TCP. Port 53 needs root or `CAP_NET_BIND_SERVICE`. |
| `dns.private_domain` | `home.arpa` | Reserved for this purpose by RFC 8375. |
| `dns.reverse_zones` | none | CIDRs to derive PTR records for. |
| `dns.upstreams` | `1.1.1.1:53`, `9.9.9.9:53` | Tried in order. `host:port` required. |
| `dns.allow_query` | loopback, RFC1918, ULA | Default-closed; everything else gets `REFUSED`. |
| `dns.allow_tailscale` | `false` | Adds `100.64.0.0/10`. See below. |
| `dns.ttl` | `60` | TTL on authoritative answers. |
| `dns.cache_min_ttl` | `5` | Lower clamp on upstream TTLs. |
| `dns.cache_max_ttl` | `3600` | Upper clamp on upstream TTLs. |
| `dns.negative_max_ttl` | `300` | Clamp on RFC 2308 negative caching. |
| `dns.cache_entries` | `10000` | LRU size. Authoritative answers are never cached. |
| `dns.log_queries` | `false` | Logs name, type, rcode, view, duration. |
| `dns.log_client_ip` | `false` | Separate opt-in; query logging alone does not record who asked. |
| `admin.listen` | `127.0.0.1:8053` | Web UI and JSON API. Plain HTTP — proxy it for TLS. |
| `discovery.dhcp_lease_file` | none | Off until set. dnsmasq format. |
| `discovery.interval` | `30` | Seconds between lease re-reads. |
| `health.interval` | `30` | Seconds between probes. |
| `health.timeout` | `5` | Per-probe timeout. |
| `health.workers` | `8` | Concurrent probes. |

### Tailscale

Tailscale addresses are CGNAT (`100.64.0.0/10`), not RFC1918, so they are **not**
covered by the default `allow_query`. Leave `allow_tailscale: false` unless you
use Tailscale — some ISPs also assign CGNAT addresses, which would make the
range a standing exposure on a WAN-facing interface.

While it is off, tailnet clients get `REFUSED`. KyDNS says so rather than
failing silently: the dashboard shows a banner, the Settings screen flags any
view that can never match, and the startup log warns.

To give one name a LAN answer and a tailnet answer, add a view for
`100.64.0.0/10` and give the service a second address tagged with it.

## Running it

```sh
kydns serve --config /etc/kydns/kydns.yaml
```

On first start with no admin account, KyDNS writes a setup token to
`<data_dir>/setup-token` and logs it. Open the admin listener, enter that
token, and choose a password. A bootstrap API token for the CLI is written to
`<data_dir>/bootstrap-token`.

The CLI reads `KYDNS_URL` (default `http://127.0.0.1:8053`) and `KYDNS_TOKEN`.

### Docker

```sh
cp kydns.example.yaml kydns.yaml    # set data_dir: /var/lib/kydns
docker compose up -d
docker compose logs kydns | grep setup-token
```

The compose file uses **host networking**, so KyDNS binds port 53 on the host
directly with no port mapping. Note that host networking does not give the
container its own IP address — it answers on the host's. `docker-compose.yml`
documents a macvlan alternative if you want a separate LAN address.

Two things that bite:

- **Port 53 is usually taken.** `sudo ss -ulpn 'sport = :53'` will show
  systemd-resolved, dnsmasq, or avahi holding it. The compose file has the
  systemd-resolved fix.
- **Use the named volume for `data_dir`, not a host directory.** The container
  drops all capabilities except `NET_BIND_SERVICE`, which means it loses
  `CAP_DAC_OVERRIDE` and cannot write into a directory owned by another user.
  A bind mount from your home directory fails with `unable to open database
  file`. Chown it to root if you need one.

The image is distroless and about 29 MB. It has no shell, so read the
first-run tokens from the volume rather than with `docker exec`:

```sh
docker run --rm -v kydns_kydns-data:/d busybox cat /d/setup-token
```

## Security model

- DNS data stays on the operator's network.
- The server does not send query history to a KySecurity service.
- Administrative changes require authentication and are recorded locally.
- Configuration exports must not contain upstream credentials or private keys.
- Public DNS names and private service names remain separate by default.

See [DESGINE.md](DESGINE.md) for the architecture, [LOGGING.md](LOGGING.md)
for logging requirements, and [SECURITY.md](SECURITY.md) for security policy.

## Initial scope

The first version provides a small DNS server, a service registry, and a simple
web UI. It solves local naming well before adding ad blocking, parental
controls, device posture, or traffic inspection.

## Repository status

v1 is implemented. See
[the design spec](docs/superpowers/specs/2026-08-11-kydns-v1-design.md) for the
architecture and the reasoning behind each decision.

```sh
make test    # every package
make build   # bin/kydns
```
