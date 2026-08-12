# KyDNS

KyDNS is a self-hosted local DNS server and service directory for homes,
homelabs, and small teams.

Its primary job is to make private services easy to name and reach. It also
provides opt-out DNS blackhole filtering with built-in and operator-managed
lists.

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

- First-class services, each with its own address records and aliases, plus
  derived reverse records. Manual A, AAAA, and CNAME records for anything a
  service doesn't cover.
- A configurable private domain, `home.arpa` by default.
- Per-subnet views: one name can answer differently on the LAN and over a VPN.
- DHCP lease discovery from dnsmasq, with promote-to-service.
- Health checks over HTTP, HTTPS, and TCP, with status in the web interface.
- Upstream forwarding over DNS-over-TLS and DNS-over-HTTPS, with a cache,
  sequential failover, and single-flight.
- A web UI, a JSON API, and a CLI that talks to the API.
- Built-in and custom DNS blacklists, one-off allow/deny rules, and a one-button
  filtering toggle. Filtering is enabled by default and never overrides local
  records.
- YAML and JSON import/export for backup and Git-based configuration.

### Blacklist filtering

The web UI's Blacklists tab has a global on/off toggle, the built-in list
(StevenBlack's unified hosts file, MIT licensed), any custom lists an
operator adds by URL, and one-off allow/deny rules. Lists come in three
formats: plain domains, hosts-file syntax, and Adblock Plus-style rules.

Precedence is deny beats allow beats lists: a deny rule always blocks, an
allow rule always overrides a list, and lists only apply where no rule says
otherwise. Matching is on label boundaries, so a rule or list entry for
`ads.example` also blocks `sub.ads.example` but never `badads.example`.

A blocked name gets a local NXDOMAIN with the authoritative (AA) bit clear
and never reaches an upstream resolver. A KyDNS service or manual record can
never be blocked: the policy is only consulted after the authoritative
lookup declines to answer.

This is domain filtering, not traffic inspection, parental control, or a
malware guarantee.

## Not yet

- Linked-server replication between KyDNS peers. The store keeps a single write
  chokepoint so the change log can be added without restructuring.
- **Local DNSSEC validation.** KyDNS trusts the upstream's verdict over an
  encrypted channel; it does not verify signatures itself. An `AD` bit from
  KyDNS means "the resolver we talked to privately said it validated," not
  "KyDNS checked the chain."
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
| `dns.upstreams` | `tls://1.1.1.1:853`, `tls://9.9.9.9:853` | Tried in order. `tls://`, `https://`, or `udp://` before an **IP address**. See below. |
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

### Upstream encryption

The scheme decides how much you trust the answer:

```yaml
dns:
  upstreams:
    - tls://1.1.1.1:853              # DNS-over-TLS
    - https://9.9.9.9/dns-query      # DNS-over-HTTPS
    - udp://192.168.1.1:53           # plain DNS, opted into per upstream
```

The host must be an **IP address**. A hostname would need DNS to resolve it,
and KyDNS may be the thing resolving — on a machine that points at itself that
is a loop. Cloudflare, Quad9 and Google all present certificates valid for
their IPs, so nothing further is needed. When a provider's certificate needs a
hostname, put it after a `#`:

```yaml
    - tls://45.90.28.0:853#abc123.dns.nextdns.io
```

That sets the TLS server name while still dialling the address you gave.
Certificate verification is always on and there is no option to turn it off.

**With only encrypted upstreams, a query fails rather than falling back.** If
every one is unreachable, clients get `SERVFAIL` and the Settings screen names
the upstream and the error — usually a firewall blocking port 853. That is the
intended behaviour: silently dropping to plain DNS is exactly what an attacker
who blocks 853 is hoping for.

The escape hatch is one line. Add a `udp://` upstream and KyDNS will use it
when the encrypted ones fail. Answers it serves have the authenticated-data
flag cleared, because nothing authenticated them, and the dashboard carries a
banner for as long as the entry is there.

KyDNS is not a validating resolver. It does not verify signatures, hold a trust
anchor, or walk a chain of trust. It makes the path to a resolver that does all
of that private and tamper-proof, and passes that resolver's verdict through.

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

### Putting a service behind a reverse proxy

A service speaking plain HTTP behind a proxy that terminates TLS wants two
different addresses: clients should reach the proxy, monitoring should reach
the service.

Register the service at its **real** address, set the proxy address, and tick
"Send DNS to the proxy":

```sh
kydns service add kypost \
  --address 192.168.1.30 \
  --proxy 192.168.1.20 --via-proxy \
  --check http://192.168.1.30:8080/health
```

`kypost.home.arpa` now answers `192.168.1.20`, and so does every alias. The
reverse record for `192.168.1.30` still names `kypost.home.arpa`, so several
services behind one proxy each keep a correct PTR.

Point the health check at the service, not the proxy. A proxy returning 502 for
a dead backend still answers a prober perfectly, so checking the proxy tells you
only that the proxy is up.

Routing can be turned on or off after the service is created, which is how you
tell whether a problem is the application or the proxy: leave the address in
place and just flip the switch. The Services screen has a routing form on
each row — a proxy address field, a checkbox, and a Save button — that changes
only those two fields.

The same is true over the API: `PATCH /api/v1/services/{id}` merges the body
onto the existing service, so any field you leave out keeps its value. A body
of

```json
{"name": "grafana", "addresses": [{"address": "192.168.1.60"}]}
```

changes the name and address and leaves `aliases`, `check_url`,
`check_insecure`, `proxy_address`, and `route_via_proxy` untouched. To clear a
field explicitly, include it with an empty value (`"aliases": []`,
`"check_url": ""`); an `addresses` or `aliases` array you do provide replaces
the whole list rather than merging into it, so a routed address never
inherits a view tag from the one it replaced.

A service with both an IPv4 and an IPv6 address behind one proxy answers `A`
only: `--proxy` takes one address, so the `AAAA` query gets `NODATA` instead of
the service's own IPv6 address. Give the service just the address family the
proxy needs, or leave routing off if both must keep resolving.

## Running it

```sh
kydns serve --config /etc/kydns/kydns.yaml
```

On first start with no admin account, KyDNS writes a setup token to
`<data_dir>/setup-token` and logs it. Open the admin listener, enter that
token, and choose a password. A bootstrap API token for the CLI is written to
`<data_dir>/bootstrap-token`.

The CLI reads `KYDNS_URL` (default `http://127.0.0.1:8053`) and `KYDNS_TOKEN`.
Everything except `serve` and `admin` goes through the JSON API, so the CLI
works from any machine that can reach the admin listener:

| Command | Does |
|---|---|
| `kydns serve` | Run the DNS and admin servers. |
| `kydns service add\|list\|rm` | Manage services, their addresses and aliases. |
| `kydns record add\|list\|rm` | Manage manual A, AAAA and CNAME records. |
| `kydns view add\|list\|rm` | Manage per-subnet views. |
| `kydns token add\|list\|rm` | Manage API tokens. |
| `kydns export` / `kydns import` | Read or write the registry as YAML or JSON. |
| `kydns admin reset-password` | Local recovery. Opens the database directly. |

### Forgot the admin password

```sh
kydns admin reset-password --config /etc/kydns/kydns.yaml
```

This is the one command that opens the database directly instead of going
through the API, because there is otherwise no way back in. It needs write
access to the database file — anyone who has that can already read every hash
and token in it, so it is not an extra way in. Restart KyDNS afterwards to end
any sessions that are still signed in.

In Docker, where the image has no shell:

```sh
docker compose run --rm -it kydns admin reset-password
```

### Docker

KyDNS joins a **LAN-attached Docker network your host already owns**, so the
container gets its own IP address on your LAN, binds port 53 there, and never
contends with systemd-resolved or dnsmasq on the host. unRAID calls that
network `br0`. If AdGuard Home or Pi-hole already has a LAN address, KyDNS
joins the same network they are on.

Compose joins the network. It never creates or deletes it — a network handing
out addresses on your physical LAN outlives any one stack.

```sh
cp .env.example .env                    # set KYDNS_IP, and KYDNS_NETWORK if not br0
cp kydns.example.yaml kydns.yaml
make setup                              # detects your interface, subnet, gateway
docker compose up -d
docker compose logs kydns | grep setup-token
```

`make setup` reads the host's default route and appends the interface, subnet
and gateway to `.env`. It only adds keys that are missing, so re-running it is
safe and it never overwrites a value you set by hand. Compose creates the
network itself on `up` — there is no separate network step.

Already have the network — unRAID's `br0`, or whatever AdGuard Home and Pi-hole
are on? Set `KYDNS_NETWORK` to its name. Compose adopts it, prints a warning
saying it did not create it, and leaves it in place on `docker compose down`.
Only a network compose created itself gets removed.

In `kydns.yaml` change two settings from their defaults: `data_dir:
/var/lib/kydns`, and `admin.listen: "0.0.0.0:8053"`. Leaving admin on
`127.0.0.1` would bind the *container's* loopback, reachable from nowhere.

The image already has both set, in `kydns.docker.yaml` baked in at
`/etc/kydns/kydns.yaml`, so a `docker run` with no config mounted at all
starts and serves. The compose file mounts your `kydns.yaml` over it, which is
what makes the two settings above yours to get right. Everything else takes
the same defaults `kydns.example.yaml` documents.

Pick a `KYDNS_IP` inside that network's subnet, **outside the router's DHCP
pool**, and different from any address AdGuard Home or Pi-hole already holds.
Two DNS servers can each own port 53 at once when each has its own LAN
address, which is how you move one client at a time instead of the whole
house.

#### Pre-creating it

Compose creates the network for you. Pre-create it only if you want it shared
with other containers or kept across `compose down` — compose adopts an
existing network rather than complaining:

```sh
docker network create -d ipvlan \
  -o parent=eth0 \
  --subnet 192.168.1.0/24 --gateway 192.168.1.1 \
  --ip-range 192.168.1.53/32 \
  br0
```

The `/32` range is deliberate. Give Docker the whole subnet and it will
eventually allocate an address your router later leases to a phone, which
presents as DNS failing at unpredictable hours.

`ipvlan` shares the host's MAC and only adds an address, so switch port
security and DHCP snooping have nothing to object to, and it is the driver
that survives WiFi. `macvlan` gives each container its own MAC, which matters
only if you want the router to hold a DHCP reservation for it — KyDNS uses a
static address, so it does not. Set `KYDNS_NET_DRIVER=macvlan` if you want it
anyway.

#### Three things that bite

- **The host cannot reach the container.** macvlan and ipvlan both deliberately
  block host-to-container traffic. Everything else on the LAN is fine; only the
  Docker host itself can't reach KyDNS. That matters if the host resolves
  through it. `docker-compose.yml` has the shim-interface fix.
- **Use the named volume for `data_dir`, not a host directory.** The container
  drops all capabilities except `NET_BIND_SERVICE`, losing `CAP_DAC_OVERRIDE`,
  so it cannot write into a directory owned by another user. A bind mount from
  your home directory fails with `unable to open database file`. Chown it to
  root if you need one.
- **The image has no shell.** It is distroless, about 29 MB. Read the first-run
  tokens from the volume rather than with `docker exec`:

```sh
docker run --rm -v kydns-server_kydns-data:/d busybox cat /d/setup-token
```

#### WiFi

`ipvlan` works over WiFi, which is why it is the default. Some access points
with client isolation still interfere. Note that there is no `br0` over WiFi in
the literal sense — a station-mode interface cannot be enslaved to a Linux
bridge — but nothing here needs one: the network just has to exist under that
name, and an ipvlan network with `parent=wlan0` does.

## Security model

- DNS data stays on the operator's network.
- The server does not send query history to a KySecurity service.
- Administrative changes require authentication and are recorded locally.
- Configuration exports must not contain upstream credentials or private keys.
- Public DNS names and private service names remain separate by default.

See [DESGINE.md](DESGINE.md) for the architecture, [LOGGING.md](LOGGING.md)
for logging requirements, and [SECURITY.md](SECURITY.md) for security policy.

## Scope

KyDNS is a small DNS server, a service registry, a web UI, and opt-out DNS
blackhole filtering. It does not provide parental controls, device posture, or
traffic inspection.

## Repository status

v1 is implemented and single-node. See
[the design spec](docs/superpowers/specs/2026-08-11-kydns-v1-design.md) for the
architecture and the reasoning behind each decision.

```sh
make test    # every package
make build   # bin/kydns
```

CI runs `gofmt`, `go vet`, `go mod tidy`, the race-enabled test suite, a
cgo-free build, and a Docker job that resolves both a local service name and a
public name over the default DoT upstream.

## License

KyDNS is licensed under the [GNU AGPL v3](LICENSE). The web UI carries the
notice and serves the full license text from its About popover, so an operator
running a modified copy over a network can always see what they are running.
