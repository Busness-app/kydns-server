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
- Server settings — upstreams, the query ACL, TTLs, cache bounds, logging,
  discovery and health — edited from any of the three and applied without a
  restart. Only five keys are still in a config file.
- Linked-server replication, operable from the CLI and the web UI: pair two
  nodes by confirming a fingerprint the way you would an SSH host key, watch
  each replica's lag on the Replication screen, and promote a replica with one
  command when the primary is gone. A replica follows its primary over its own
  pinned TLS listener, keeps answering DNS when the primary is down, refuses
  administrative writes with the address of the node to make them on, and
  reports service health as unknown rather than showing you what it last heard.
  See [Replication](#replication).
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

- **Automatic failover.** Replication is one primary, chosen by you. Nothing
  elects a new one, nothing discovers peers, and a replica never promotes
  itself. Losing the primary costs administration, not resolution: give clients
  both servers and they keep resolving.
- **Local DNSSEC validation.** KyDNS trusts the upstream's verdict over an
  encrypted channel; it does not verify signatures itself. An `AD` bit from
  KyDNS means "the resolver we talked to privately said it validated," not
  "KyDNS checked the chain."
- Docker Compose discovery, and lease formats other than dnsmasq.
- Local TLS certificate issuance for private service names.

## Configuration

**Three keys live in a file, and two more if you replicate. Everything else
lives in the database and is edited in the UI.**

Copy [`kydns.example.yaml`](kydns.example.yaml) to `/etc/kydns/kydns.yaml`, or
point somewhere else with `--config`. These three are read from it at every
start, because KyDNS needs them before it has a database or a web UI:

| Setting | Default | Notes |
|---|---|---|
| `data_dir` | *required* | Holds the database and the bootstrap/setup tokens. Back it up. |
| `dns.listen` | `:53` | UDP and TCP. Port 53 needs root or `CAP_NET_BIND_SERVICE`. |
| `admin.listen` | `127.0.0.1:8053` | Web UI and JSON API. Plain HTTP — proxy it for TLS. |

Two more are read from the file only if you run more than one server:
`replication.listen` and `replication.primary`. Setting both is a startup
error. See [Replication](#replication).

All five can also come from the environment — `KYDNS_DATA_DIR`,
`KYDNS_DNS_LISTEN`, `KYDNS_ADMIN_LISTEN`, `KYDNS_REPLICATION_LISTEN`,
`KYDNS_REPLICATION_PRIMARY` — which is how a container is configured without
mounting a file. The variable wins over the file, and startup logs which
variables it applied. A variable set to nothing is ignored rather than treated
as empty, so a blank field in a container template cannot switch off something
the file turned on. Setting `replication.listen` in the file and
`KYDNS_REPLICATION_PRIMARY` in the environment is the same startup error as
setting both in the file, and the message says which source each came from.

Changing one of those means restarting KyDNS. The Settings screen shows them
read-only, so you can see what the running server actually has.

Every other setting — the private domain, reverse zones, upstreams,
`allow_query`, Tailscale, TTLs, the cache bounds, the two logging opt-ins,
lease discovery, and the health-check intervals — lives in the database.
`kydns.example.yaml` still lists them, but only as **first-run seed values**:
they populate a fresh database and are ignored on every start after that.
Editing them in the file later does nothing.

Edit them in one of three places, all of which go through the same validation
and the same write path:

```sh
kydns settings get                       # what the server is running
kydns settings set ttl=120 log_queries=true
kydns settings set allow_query=192.168.1.0/24,10.0.0.0/8
```

```sh
curl -H "Authorization: Bearer $KYDNS_TOKEN" $KYDNS_URL/api/v1/settings
curl -X PATCH -H "Authorization: Bearer $KYDNS_TOKEN" \
  -d '{"ttl":120}' $KYDNS_URL/api/v1/settings
```

`PATCH` merges: keys you leave out keep their value, so two people editing
different settings do not clobber each other. Settings are part of
`kydns export` and are applied by `kydns import`.

Almost everything applies the moment it is saved, with no restart and no
dropped queries: upstreams (which also flushes the cache), the private domain,
reverse zones, `allow_query`, `allow_tailscale`, the TTL, all four cache
settings, both log flags, the three health settings, and the discovery
interval. One cannot change in a running process — `dhcp_lease_file`, which
the discovery poller is opened against. It is saved anyway, and a banner names
the running value and the saved one until you restart.

### Renaming the private domain

Services are stored by short name and follow the zone on their own. Manual
records are stored as full names, so changing `private_domain` moves them:
`printer.home.arpa.` becomes `printer.lan.example.`, and a CNAME or PTR
pointing into the old zone is repointed with it. The Settings screen lists
every record it would move and does nothing until you save a second time. The
records and the setting are written in one transaction, so a rename cannot
half-apply, and the cache is flushed because every cached name under the old
zone is now wrong.

Records outside the private zone are left alone — they are yours, not ours to
rewrite. Clients hold the old names until their TTL expires.

### Opening `allow_query` beyond your LAN

Adding a range outside loopback, RFC1918, ULA, link-local and CGNAT would make
KyDNS an open resolver, so it takes a deliberate second step: retype the
prefix in its canonical masked form to confirm it. In the settings form that
is the confirmation box, over the API it is `confirm_public`, and on the CLI
it is `--confirm-public`:

```sh
kydns settings set allow_query=192.168.0.0/16,203.0.113.0/24 \
  --confirm-public 203.0.113.0/24
```

You are asked once, when the prefix is new. A prefix already stored counts as
confirmed, so later saves of unrelated settings never ask again. While any
public range is configured, the dashboard and the Settings screen carry a
standing banner and KyDNS logs a warning naming the prefix at every start.
See [SECURITY.md](SECURITY.md) for the full rule.

### Upgrading from a config-file deployment

- **An existing `kydns.yaml` keeps working.** On the first start after the
  upgrade its values seed the database, and from then on the database owns
  them. That includes a `dns.allow_query` that reaches past your LAN: it is
  grandfathered rather than refused, because refusing to start would take a
  working household's DNS offline over a file that was legal when it was
  written. It does log a warning naming the prefix at every start, and shows a
  standing banner, until you remove it.
- **Confirmation is asked once.** Adding a public prefix through the UI, the
  API or the CLI asks you to retype it that one time. It does not re-ask on
  every later save.
- **A backup containing a public prefix cannot be restored.** There is no
  confirmation path through import, so a document whose `allow_query` carries
  a public prefix the server is not already serving is refused. In replace
  mode that check runs *before* the destructive part, so the existing registry
  and settings are left exactly as they were rather than half-replaced. Edit
  the prefix out of the document, import it, then add the prefix back with
  `kydns settings set ... --confirm-public`.

### Upstream encryption

The upstream list is edited under Settings, one entry per line, and applies as
soon as it is saved. The scheme decides how much you trust the answer:

```text
tls://1.1.1.1:853              # DNS-over-TLS
https://9.9.9.9/dns-query      # DNS-over-HTTPS
udp://192.168.1.1:53           # plain DNS, opted into per upstream
```

The host must be an **IP address**. A hostname would need DNS to resolve it,
and KyDNS may be the thing resolving — on a machine that points at itself that
is a loop. Cloudflare, Quad9 and Google all present certificates valid for
their IPs, so nothing further is needed. When a provider's certificate needs a
hostname, put it after a `#`:

```text
tls://45.90.28.0:853#abc123.dns.nextdns.io
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
covered by the default `allow_query`. Leave "Allow Tailscale addresses" off
unless you use Tailscale — some ISPs also assign CGNAT addresses, which would
make the range a standing exposure on a WAN-facing interface. It is a checkbox
under Settings, or `kydns settings set allow_tailscale=true`, and it takes
effect at once.

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

## Replication

A second KyDNS keeps resolving while the first one is down. One node is the
primary and takes every change; the other follows it and serves the same
answers read-only. Give your clients both addresses.

Both `replication` keys are owned by the config file, so each step here that
sets one needs a restart. On the primary:

```yaml
replication:
  listen: "192.168.1.10:8443"   # its own TLS listener, separate from DNS and the UI
```

On the node that will follow it:

```yaml
replication:
  primary: "192.168.1.10:8443"
```

Restart both, then pair them. Pairing works like an SSH host key: the primary
prints a code and its fingerprint, and the other node reports the fingerprint
of whoever answered before the code is ever sent.

```sh
kydns replica invite                  # on the primary: a code and a fingerprint
kydns replica join 192.168.1.10:8443 <code> --fingerprint <fingerprint>
kydns replica list                    # on the primary: lag and last sync per replica
kydns replica status                  # on a replica: what it follows, and why a poll failed
```

Compare the two fingerprints yourself. Without `--fingerprint`, `join` shows
you the one it was presented and waits for a yes; if it does not match, say no.
A mismatch means something is answering in the primary's place, and the code is
not sent, so it stays good.

Restart the replica once more after joining — the pull loop is built at
startup. From then on it polls every five seconds, and a change on the primary
is answered by the replica a few seconds later. Writes on the replica are
refused with the address of the primary to make them on: in the API, in the
CLI, and in the UI, whose editing controls are disabled with the same reason.

The Replication screen in the web UI does all of this too: minting an invite,
pairing a replica with the primary its config names, listing replicas with
their lag, removing one, and promoting. The screen pairs with
`replication.primary` and never an address you type, because that is the
address the pull loop dials.

### When the primary is down

The replica keeps answering every name it last pulled, for as long as it takes.
It shows how long since its last sync, and puts up a standing banner once that
passes a minute. Service health reads as unknown, not as the last thing it
heard: the node that runs the checks is the one that is missing.

Promote it once you have decided the primary is not coming back:

```sh
kydns replica promote
```

It accepts writes immediately. Two things are then yours to do:

- Set `replication.listen` on it and restart, or nothing can follow it.
  Promotion opens no listener and does not edit your config file.
- Do not switch the old primary back on until it has been demoted or rebuilt.
  Demote it with `kydns replica join` against the new primary, which discards
  its configuration on the first pull. Two primaries serving the same replicas
  is the one state KyDNS can neither detect nor undo.

Demoting an old primary means editing both keys in its config: set
`replication.primary` to the new primary, and remove the `replication.listen`
it still has from when it was one. A node with both keys refuses to start, so
setting only the first leaves that box with no DNS at all.

The promotion is recorded in the database, so a promoted node comes back a
primary at every later start even though `replication.primary` is still in its
file. It logs that the key is being ignored; remove it when convenient.

There is no automatic failover, no leader election, and no peer discovery.
Promotion is a decision you make, and one primary is the only supported shape.

## Install from a package

Debian and Ubuntu, including Raspberry Pi OS, on `amd64` and `arm64`:

```sh
# pick the .deb matching your architecture from the latest release
curl -LO https://github.com/yoshiofthewire/kydns-server/releases/latest/download/kydns_<version>_arm64.deb
```

Verify it came from this repository's CI before installing:

```sh
gh attestation verify kydns_<version>_arm64.deb --repo yoshiofthewire/kydns-server
sudo apt install ./kydns_<version>_arm64.deb
```

Fedora, and the RHEL 9 and 10 family including Rocky and Alma, on `x86_64`
and `aarch64`:

```sh
# pick the .rpm matching your architecture from the latest release
curl -LO https://github.com/yoshiofthewire/kydns-server/releases/latest/download/kydns-<version>-1.aarch64.rpm
gh attestation verify kydns-<version>-1.aarch64.rpm --repo yoshiofthewire/kydns-server
sudo dnf install ./kydns-<version>-1.aarch64.rpm
```

Neither package starts KyDNS, because it wants port 53 and your host may
already run a resolver. Check first:

```sh
sudo ss -lnup 'sport = :53'
```

The `.deb` is enabled at boot already, so it only needs starting:

```sh
sudo systemctl start kydns
```

The `.rpm` follows your host's systemd presets, which leave a new service
disabled, so it needs both:

```sh
sudo systemctl enable --now kydns
```

Then read the one-time setup token:

```sh
sudo cat /var/lib/kydns/setup-token
```

The web UI listens on `127.0.0.1:8053` only. KyDNS speaks plain HTTP, so reach
it over an SSH tunnel:

```sh
ssh -L 8053:127.0.0.1:8053 <this-host>
```

then open `http://127.0.0.1:8053/setup` and enter the token to create your
admin account. To publish the UI on your LAN instead, change `admin.listen`
in `/etc/kydns/kydns.yaml` to `0.0.0.0:8053` — and put a TLS-terminating
reverse proxy in front of it.

| Path | What it is |
|---|---|
| `/etc/kydns/kydns.yaml` | Configuration. Your edits survive upgrades. |
| `/var/lib/kydns` | Database and tokens. **Back this up.** |
| `/usr/share/doc/kydns/kydns.example.yaml` | Every setting, documented. |
| `/usr/share/doc/kydns/copyright`, `/usr/share/licenses/kydns/LICENSE.txt` | The MIT licence text, deb and rpm respectively. |

Removing the package leaves `/var/lib/kydns` in place — with `apt purge` and
with `dnf remove` alike. It holds your whole registry and every credential.
Delete it yourself when you are sure.

## Raspberry Pi SD image

For a Raspberry Pi 3, 4, 5, or Zero 2 W running 64-bit Raspberry Pi OS Lite,
build the image from the arm64 package:

```sh
make rpi-image VERSION=0.0.0-dev
sudo dd if=dist/kydns_0.0.0-dev_rpi64.img of=/dev/sdX bs=4M status=progress conv=fsync
```

The tagged release asset is compressed to `*.img.xz`; unpack it with
`xz -d` before flashing.

Replace `/dev/sdX` with the whole SD card device. The image is a Raspberry Pi
OS Lite base, not a new distribution. On its first boot it installs the
staged `.deb`, enables KyDNS, and starts it. Raspberry Pi OS first-boot setup
still supplies the normal user, password, hostname, and network choices; the
image needs network access on that boot. Read the setup token with:

```sh
sudo cat /var/lib/kydns/setup-token
```

The base is pinned. `packaging/rpi-base.pin` names one official arm64 Lite
release and the SHA-256 Raspberry Pi published for it, and the builder refuses
a download that does not match — a release is signed and attested, so what it
was built on top of is a reviewed decision rather than whatever the mirror
served that morning. A weekly job proposes the next release once it has been
out for three days; `RPI_BASE_URL` and `RPI_BASE_SHA256` override the pin for
a local build. The output is not safe to flash while compressed and is
intentionally not a raw device path.

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
| `kydns settings get` | Print the settings the server is running. |
| `kydns settings set k=v ...` | Change them. `--confirm-public <cidr>` for a public `allow_query` range. |
| `kydns replica invite\|list\|remove` | Manage the replicas this node serves. `invite` prints a pairing code and this node's fingerprint; confirm the fingerprint on the replica before entering the code. |
| `kydns export` / `kydns import` | Read or write the registry and settings as YAML or JSON. |
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

In `kydns.yaml` change two of the three file-owned settings from their
defaults: `data_dir: /var/lib/kydns`, and `admin.listen: "0.0.0.0:8053"`.
Leaving admin on `127.0.0.1` would bind the *container's* loopback, reachable
from nowhere. `dns.listen` is already right at `:53`.

The image already has both set, in `kydns.docker.yaml` baked in at
`/etc/kydns/kydns.yaml`, so a `docker run` with no config mounted at all
starts and serves. The compose file mounts your `kydns.yaml` over it, which is
what makes the two settings above yours to get right. Nothing else needs to be
in that file: every other setting seeds the database on the first run and is
edited under Settings from then on.

Pick a `KYDNS_IP` inside that network's subnet, **outside the router's DHCP
pool**, and different from any address AdGuard Home or Pi-hole already holds.
Two DNS servers can each own port 53 at once when each has its own LAN
address, which is how you move one client at a time instead of the whole
house.

#### Unraid

On Unraid there is no YAML to edit at all. The three keys a single server needs
are the container template's job: one volume mapping for `data_dir`, and two
port mappings for `dns.listen` and `admin.listen`. The baked-in
`kydns.docker.yaml` already sets the two that need it, and the template's
mappings decide where they land on the host.

Replication is the fourth, and it has no port mapping to stand in for it. Add
it as a template **Variable** rather than mounting a config file: Edit the
container, *Add another Path, Port, Variable...*, Config Type **Variable**, Key
`KYDNS_REPLICATION_LISTEN`, Value `0.0.0.0:8443` for a primary — or
`KYDNS_REPLICATION_PRIMARY` with the primary's `host:port` for a replica.
Apply, which restarts the container, which is what picking up a file-owned key
takes anyway. On a `br0` address that port needs no mapping; it is already on
the container's own LAN address.

Set the container on your `br0` network so it gets its own LAN address, start
it, read the setup token from the log, and do everything else — upstreams, the
private domain, filtering, `allow_query` — from the web UI.

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

v1 is implemented, and a single node is still the normal deployment. See
[the design spec](docs/superpowers/specs/2026-08-11-kydns-v1-design.md) for the
architecture and the reasoning behind each decision, and
[the replication spec](docs/superpowers/specs/2026-08-13-kydns-linked-server-replication-design.md)
for the second node.

```sh
make test    # every package
make build   # bin/kydns
```

CI runs `gofmt`, `go vet`, `go mod tidy`, the race-enabled test suite, a
cgo-free build, and a Docker job that resolves both a local service name and a
public name over the default DoT upstream.

## License

KyDNS is licensed under the [MIT License](LICENSE.txt). The web UI carries the
notice and serves the full license text from its About popover, so an operator
can always see the terms of what they are running.
