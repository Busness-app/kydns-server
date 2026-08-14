# Release packaging

Status: approved
Date: 2026-08-13

## Why

KyDNS ships one artifact today: a multi-arch container image on GHCR. There is
no release workflow, no versioned binary, and no way to install KyDNS on a host
without Docker. `ci.yml` lints, tests, runs an integration check, and pushes the
image — that is the whole delivery story.

The immediate demand is a Raspberry Pi appliance: flash a card, get a DNS
server. That is a real product with its own first-boot, signing, and update
concerns, and it is **not** this spec. This spec builds the layer underneath it,
because an appliance image whose only update path is "reflash the card" is a
liability. A DNS server that never gets patched is worse than no appliance.

Packaged first, imaged later. The package is independently useful — it serves
every Linux host, not just Pi owners — and it turns the eventual image into a
thin wrapper around a maintained package rather than a separate artifact with
its own lifecycle.

## Decisions

| Question | Decision |
|---|---|
| Artifacts | Tarball and `.deb`, per architecture, plus `SHA256SUMS`. |
| Architectures | `linux/amd64` and `linux/arm64`. |
| `.rpm` | Not in v1. |
| Trigger | Tag push matching `v*`, in a new workflow. |
| Provenance | GitHub build attestations, keyless. |
| Service user | Static system user `kydns`, not `DynamicUser`. |
| Privilege | `CAP_NET_BIND_SERVICE` only. Never root. |
| Config on upgrade | Preserved (`config|noreplace`). |
| Data on purge | Never removed. |
| Admin listen default | `127.0.0.1:8053`, unchanged from upstream default. |
| apt repository | Not in v1. |

## What the code already supports

Three findings from `internal/` set the shape of the package. None require
source changes.

**Exactly two listeners, one privileged.** `app.Serve` binds `cfg.DNS.Listen`
(default `:53`) and `cfg.Admin.Listen` (default `127.0.0.1:8053`) —
`internal/app/serve.go:253,259`. The DNS server opens UDP and TCP on that single
address, `internal/dnsserver/server.go:262-268`. There is no `SO_BINDTODEVICE`
and no per-interface bind anywhere in the tree.

Per-subnet views do not change this. A view is a string resolved from the
client's source address and passed into `Answer(snap, view, q)`
(`internal/dnsserver/auth.go:114`) — answer selection, not a second socket.

So `CAP_NET_BIND_SERVICE` is sufficient. No root, no setuid.

**The config file is never written.** The only two `os.WriteFile` calls in the
tree write the bootstrap and setup tokens into the data dir at `0600`
(`internal/app/serve.go:408,456`). Three settings are file-owned — `data_dir`,
`dns.listen`, `admin.listen` — and everything else lives in SQLite under
`data_dir`. That gives a clean split: read-only `/etc`, one writable state
directory.

**The config holds no secrets.** Every field in `config.Config`
(`internal/config/config.go:23-66`) is operational: listens, upstreams, TTLs,
ACLs, discovery paths, health tuning. Credentials live in the database. The
config file can therefore be world-readable without a caveat.

## Version stamping

There is no version string in the tree. `cmd/kydns/main.go` has no `version`
variable and no `version` subcommand. A package needs a version, and a bug
report needs one more.

This is the only source change in the spec:

- `var version = "dev"` in `main.go`, set at link time with
  `-ldflags "-X main.version=$VERSION"`.
- A `version` case in the existing `switch` (`main.go:36`) printing the string,
  and a matching line in `usage`.
- The same `-X` flag added to the `Dockerfile` build, so the container and the
  package report identical versions.

## Release workflow

New `.github/workflows/release.yml`, triggered on `push: tags: ['v*']`. It is
separate from `ci.yml` so the tag path can hold `contents: write` and
`attestations: write` without widening permissions on every pull request build.

Builds use `CGO_ENABLED=0` and `-trimpath`, matching the `Makefile` and
`Dockerfile`.

Per architecture:

- `kydns_<version>_linux_<arch>.tar.gz` — the binary, `kydns.example.yaml`,
  `LICENSE`.
- `kydns_<version>_<arch>.deb`.

Then one `SHA256SUMS` covering every asset.

Provenance uses `actions/attest-build-provenance` rather than managed cosign
keys: it is keyless, free, and verifiable with `gh attestation verify`. Signing
from the first release is much cheaper than retrofitting it once people are
already downloading unsigned binaries.

## Package layout

One `nfpm.yaml`, invoked once per architecture. `nfpm` is chosen over `fpm`
because it is a single Go binary driven by one YAML file, with no Ruby
toolchain.

| Path | Owner | Mode | Notes |
|---|---|---|---|
| `/usr/bin/kydns` | root | 0755 | |
| `/lib/systemd/system/kydns.service` | root | 0644 | |
| `/etc/kydns/kydns.yaml` | root | 0644 | `config\|noreplace` |
| `/usr/share/doc/kydns/kydns.example.yaml` | root | 0644 | reference copy |
| `/var/lib/kydns` | kydns | 0700 | created by systemd `StateDirectory` |

`Depends: ca-certificates`. DoT and DoH upstreams and HTTPS health checks need a
trust store. The distroless base supplies one implicitly; a `.deb` has to ask.

`License: AGPL-3.0-or-later`, matching `LICENSE`.

The shipped config sets `data_dir: /var/lib/kydns` and otherwise keeps upstream
defaults, including `admin.listen: 127.0.0.1:8053`. A native install must not
silently expose its admin interface to the LAN. Exposing it is an explicit
operator edit; the appliance image can make that call for itself later.

`0644` on the config follows from the config holding no secrets. Secrets are in
the database, under `0700`.

### Maintainer scripts

`preinst` creates the system user, portably across Debian and RPM hosts:

```sh
id -u kydns >/dev/null 2>&1 || \
  useradd --system --no-create-home --shell /usr/sbin/nologin kydns
```

`postinst` runs `systemctl daemon-reload` and enables the unit. `prerm` stops
and disables it.

**`postrm` never removes `/var/lib/kydns`, including on purge.** It prints the
path and tells the operator to remove it themselves. That directory holds the
entire registry and every credential; `apt purge` must not be able to destroy
it. This is the one deliberately surprising behaviour in the package, and it
earns a comment in the packaging explaining itself, because here the surprising
option is the safe one.

### Rejected: `DynamicUser`

`DynamicUser=yes` with `StateDirectory` would remove the `preinst` user
creation entirely and work identically on Debian and RPM. It is rejected
because the transient UID changes between boots, leaving `/var/lib/kydns` owned
by a number that means nothing to an operator reading `ls -l` during an
incident. Predictable ownership is worth six lines of shell.

## The unit

`Type=simple`, `User=kydns`, `Restart=on-failure`,
`ExecStart=/usr/bin/kydns serve --config /etc/kydns/kydns.yaml` — already the
binary's built-in default path (`main.go:40`).

Hardening follows directly from what the code does: two binds, one privileged
port, one writable directory.

```ini
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
StateDirectory=kydns
StateDirectoryMode=0700
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SystemCallFilter=@system-service
SystemCallArchitectures=native
UMask=0077
```

Plus the conventional `ProtectKernelTunables`, `ProtectKernelModules`,
`ProtectKernelLogs`, `ProtectControlGroups`, `ProtectClock`, `ProtectHostname`,
`RestrictNamespaces`, `RestrictRealtime`, `RestrictSUIDSGID`, and
`LockPersonality`.

These are proposed, not proven. A tight `SystemCallFilter` can break a Go
runtime in ways that only appear under load, and `ProtectSystem=strict` breaks
anything writing outside `StateDirectory`. The verification section is how the
claim gets tested rather than asserted.

`MemoryDenyWriteExecute` is deliberately omitted from the initial set. It is
added only if the smoke test passes with it, not on the assumption that Go
never needs writable-executable pages.

## Verification

Every safety property claimed above has a test. The matrix runs on
`ubuntu-latest` and `ubuntu-24.04-arm`, so the arm64 package is tested on real
arm64 rather than assumed to work.

1. **Install** — install the `.deb`, start the unit, assert it reaches active.
2. **Function** — register a name, `dig` it against `127.0.0.1:53`, assert the
   answer. This is what proves `CAP_NET_BIND_SERVICE` is actually sufficient.
3. **Non-root** — read `/proc/$MAINPID/status`, assert `Uid` is not 0.
4. **Permissions** — `/var/lib/kydns` is `0700` and owned by `kydns`;
   `setup-token` is `0600`.
5. **Hardening** — record `systemd-analyze security kydns.service` and fail if
   the score regresses past a pinned threshold.
6. **Upgrade** — install, edit `/etc/kydns/kydns.yaml`, install a newer build,
   assert the edit survived.
7. **Purge** — `apt purge`, assert `/var/lib/kydns` still exists.

Tests 6 and 7 matter most and are the easiest to skip. They are the difference
between believing the package is safe and knowing it.

## Out of scope

| Excluded | Why |
|---|---|
| The Pi image | Its own spec. Depends on this one existing. |
| `armv6`/`armv7` | Cheap to build, not cheap to test. Excludes Pi Zero W, Pi 1, and 32-bit Pi OS — revisit on demand. |
| `.rpm` | `nfpm` emits it nearly free, but an untested package is worse than no package. |
| An apt repository | Without one, upgrading means downloading a new `.deb`. A GitHub Pages repository is the natural follow-on and completes the update story the image will need. |
| Changing `admin.listen` defaults | Belongs to whoever ships the appliance, not to the package. |

## Notes for the image spec

Two constraints this work hands forward, recorded here so they are not
rediscovered later.

`ensureSetupToken` (`internal/app/serve.go:442`) mints a random 128-bit token
when no admin account exists, writes it `0600` into the data dir, logs it, and
gates `/setup` on it. There is no default password to inherit — the per-device
secret is generated on first run.

That only holds if **the image ships with an empty `data_dir`**. If an image
build ever runs KyDNS to pre-initialise it, every flashed card carries the same
setup token and the same database. The image build needs an assertion that
`/var/lib/kydns` is empty, not a comment asking politely.

Second: `admin.listen: 127.0.0.1:8053` is unreachable on a headless Pi, so the
image must bind it to the LAN. That is a deliberate exposure decision — gated by
the setup token and then an admin account — and belongs in the image spec, not
here.
