# RPM packaging

Status: approved
Date: 2026-08-14

Supersedes the `.rpm` row of
`docs/superpowers/specs/2026-08-13-kydns-release-packaging-design.md`, which
deferred it out of v1.

## Why

KyDNS installs on a host two ways today: a container image, or a `.deb`. The
Fedora and RHEL-family half of the homelab audience has neither — they get the
tarball and a unit file they have to wire up themselves, which is exactly the
manual, undocumented, unpatched install the packaging spec was written to
eliminate.

The earlier spec deferred `.rpm` with a one-line reason that still holds:
"`nfpm` emits it nearly free, but an untested package is worse than no
package." That is the whole design problem. Emitting the file is a Makefile
line. This spec is about the other 90%: proving the file, and deciding where
the rpm must behave differently from the deb rather than pretending one
package shape fits both.

## Verified before designing

Every claim here was produced by building an rpm from the current `nfpm.yaml`
and querying it, not by reasoning about rpm in the abstract.

**The current config already emits a valid rpm.** `nfpm package -p rpm` with no
edits produced `VERSION=0.0.0~test`, `RELEASE=1`, `ARCH=x86_64`,
`LICENSE=AGPL-3.0-or-later`, a `SUMMARY` derived from the first line of the
description, `ca-certificates` in `--requires`, and `/etc/kydns/kydns.yaml`
listed by `--configfiles`.

**`nfpm` rewrites `-` to `~` in the rpm version.** `0.0.0-test` became
`0.0.0~test`. This is correct rpm ordering semantics — `1.0.0~rc1` sorts below
`1.0.0` — but it means the rpm filename cannot be derived from the deb's
convention. CI and the release workflow must construct it.

**`/lib/systemd/system` needs no override.** rpm resolves the `/lib` →
`/usr/lib` symlink at install time. `rpm -i` succeeded on both `fedora:latest`
and `rockylinux:9`, landing the unit at `/usr/lib/systemd/system/kydns.service`.
No `packager:`-scoped path split is required, and none is added.

**The deb's maintainer scripts are dead code under rpm.** `rpm -qp --scripts`
shows `packaging/postinst.sh` embedded verbatim, gated on `[ "$1" = "configure" ]`,
which rpm never passes — it passes `1` on install and `2` on upgrade. Installed
as-is the rpm would never enable, never restart on upgrade, and never print the
setup banner. `packaging/preinst.sh`'s `useradd` is portable and worked on both
distributions.

**`packaging/postrm.sh` carries a live bug, and it isn't rpm-only.** Its
`/var/lib/kydns` notice is outside any argument guard, so an rpm *upgrade* —
`postun` with `1` — would tell an operator their data was left behind by a
removal that never happened. The same is true of the shipped deb: dpkg calls
`postrm upgrade`, and this script prints the same false notice. The rpm
scriptlets fix it. The deb's fix is deliberately deferred, to keep this
change's zero-regression property for the package already shipping.

## Decisions

| Question | Decision |
|---|---|
| Artifacts | Add `.rpm` per architecture, alongside the tarball and `.deb`. |
| Architectures | `x86_64` and `aarch64`, matching the existing two. |
| Supported distributions | Fedora, and the RHEL 9/10 family (Rocky, Alma, RHEL). |
| Enablement on install | Follow systemd presets. **Diverges from the deb.** |
| Maintainer scripts | Separate `packaging/rpm/`, not a branch in the deb's. |
| Verification | One `verify-package.sh` with a backend per format. |
| Install testing | Privileged container running real systemd, three legs. |
| SELinux enforcing | **Untested.** Stated as a gap, not claimed as working. |
| Signing | None. Attestation only, as with the deb. |
| yum/dnf repository | Not in scope, as with apt. |
| openSUSE | Not supported. A third user-creation and packaging path. |

## Enablement diverges from the deb, deliberately

The deb enables `kydns.service` on install and leaves it stopped. The rpm runs
`systemctl preset` and leaves it neither enabled nor started.

This is a real behavioural difference between two packages of the same
software, and it is chosen rather than inherited. Fedora's packaging
guidelines reserve enablement for the host's preset policy; a package that
enables itself overrides a decision the sysadmin may have made deliberately.
Debian's convention is the opposite, and the deb follows it.

The cost is honest and goes in the README: an operator who installs the rpm,
starts it by hand, and reboots loses DNS. The mitigation is that the rpm's
first-install banner says `systemctl enable --now kydns`, where the deb's says
`systemctl start kydns`. Neither package starts a DNS server unasked on a host
that may already run a resolver — that part is common to both, and is the
safety property that actually matters.

## Package layout

`nfpm.yaml` changes in two places only.

**The licence file.** The existing `LICENSE` → `/usr/share/doc/kydns/copyright`
entry is tagged `packager: deb`; its comment already explains why Debian needs
it. An rpm sibling ships the same file to `/usr/share/licenses/kydns/LICENSE`
with `type: license`, which is where an rpm host looks and what `rpm -qL`
reports.

**The scripts block.** `scripts:` moves under `overrides.deb.scripts`, and
`overrides.rpm.scripts` points at `packaging/rpm/`.

Everything else is already correct for both formats: `depends: ca-certificates`
is the right package name on Fedora and RHEL, `config|noreplace` maps to
`%config(noreplace)`, and the deliberate absence of `/var/lib/kydns` from
`contents` keeps rpm from ever believing it owns the database.

## Maintainer scripts

Separate files, because with presets the two packages no longer do the same
thing by different means — they run different state machines. The deb's
scripts encode dpkg-specific reasoning with no rpm analogue: mask-instead-of-
disable on remove, and `deb-systemd-helper was-enabled` reading an absent
record as enabled. Branching both state machines into one file would leave
half of every script unreachable on any given install, and would need a block
of comment defending why that is not a bug.

The deb's four scripts are not touched by this change.

`packaging/rpm/preinstall.sh` — the same `useradd` as the deb's, which was
verified to work on both distributions. The one genuine duplication, and it is
four lines.

`packaging/rpm/postinstall.sh` — `daemon-reload` always. On first install
(`$1` is `1`), `systemctl preset kydns.service`, then the banner telling the
operator to check port 53 and `systemctl enable --now kydns`. On upgrade (`$1`
is `2`), `try-restart` and no banner, so a shipped security fix actually
replaces the running process.

`packaging/rpm/preuninstall.sh` — on uninstall (`$1` is `0`),
`systemctl --no-reload disable --now kydns.service`. Disabling here is safe in
a way it is not for dpkg: rpm has no config-files state for a later reinstall
to misread.

`packaging/rpm/postuninstall.sh` — `daemon-reload`, and the "your data is still
in `/var/lib/kydns`" notice **gated on `$1` being `0`**. That guard is the fix
for the bug noted above.

## Build

`Makefile`'s `package` target gains a second `nfpm` invocation per
architecture with `-p rpm`, writing
`dist/kydns-$(RPMVERSION)-1.$(rpmarch).rpm`, where `RPMVERSION` is `VERSION`
with `-` replaced by `~`, and `rpmarch` maps `amd64` → `x86_64` and `arm64` →
`aarch64`.

The name is constructed explicitly rather than letting `nfpm` auto-name into a
directory, so that CI and the release workflow can refer to a file they know
the name of instead of globbing for whatever appeared.

## Verification

`scripts/verify-package.sh` takes a `case` on the file extension. The deb
branch is today's code, unchanged. The rpm branch asserts the same contract
through `rpm -qlvp`, `rpm -qp --requires`, `--configfiles`, `--scripts`, and
`--qf '%{ARCH}'`.

One script rather than two, because the contract is identical and only the
query tool differs: the same paths, the same modes, the same `ca-certificates`
dependency, the same registration of `/etc/kydns/kydns.yaml` as a config file,
and the same assertion that `/var/lib/kydns` is absent from the manifest. Two
scripts asserting one contract would drift. This is the opposite call from the
maintainer scripts, for the opposite reason.

## Install testing

A new `package-rpm` job. The existing `package` job is untouched.

Neither `fedora:latest` nor `rockylinux:9` ships `systemd`, so a small
`scripts/rpm-test/Dockerfile` with a `FROM ${BASE}` argument installs
`systemd`, `iproute`, `bind-utils`, `curl`, and `procps-ng`. CI builds it per
leg and runs it with `--privileged --cgroupns=host` and the cgroup mount, with
`/usr/sbin/init` as PID 1. Every step is a `docker exec`.

Three legs, covering each risk axis once rather than the full matrix —
distribution varies the systemd version, architecture varies the binary:

| Leg | Runner | Image |
|---|---|---|
| Fedora / amd64 | `ubuntu-latest` | `fedora:latest` |
| Fedora / arm64 | `ubuntu-24.04-arm` | `fedora:latest` |
| Rocky 9 / amd64 | `ubuntu-latest` | `rockylinux:9` |

Rocky 9 earns its leg: its older systemd is where a hardening directive is
most likely to be silently ignored, which is what the `assert_show` checks
exist to catch.

The assertions mirror the deb suite — installs, runs as `kydns` and not root,
`/var/lib/kydns` is `700 kydns` with `600` tokens, the unit's `User`,
`AmbientCapabilities`, `CapabilityBoundingSet`, `NoNewPrivileges`, and
`ProtectSystem` are in force, and a name registered over the API resolves on a
privileged port — with three that change shape:

**Enablement inverts.** After install, assert the unit is neither enabled nor
active. Then `systemctl enable --now kydns` and assert it comes up. This is the
preset contract, and asserting it is what keeps a future edit from quietly
reverting to the deb's behaviour.

**`.rpmnew`, not `.dpkg-dist`.** Append an operator edit, build `9.9.9-upgrade`
with a deliberately changed template, `rpm -U`, then assert the edit survived,
the marker did not reach the live file, `.rpmnew` exists — which is what proves
the modified-config path was actually exercised — and the process restarted.

**No purge.** `dnf remove` is the whole removal story. Assert
`/var/lib/kydns/kydns.db` survives it.

## Release workflow

`release.yml` verifies both rpms alongside both debs, adds `*.rpm` to
`SHA256SUMS`, to the attestation `subject-path`, to the uploaded artifact, and
to `gh release create`.

The tag validation at `release.yml:36-45` needs no change. It already rejects
anything outside `[0-9A-Za-z.+~_-]`, and the `~` form is derived downstream
from an already-validated tag. A tag `v1.0.0-rc1` therefore ships `1.0.0-rc1`
as a deb and `1.0.0~rc1` as an rpm; the release notes say so.

## Documentation

`README.md`'s "Install from a package" section gains a Fedora and RHEL block:
`dnf install ./kydns-<version>-1.x86_64.rpm`, the same `gh attestation verify`
step, and start instructions that differ on purpose — `systemctl enable --now
kydns` rather than `systemctl start kydns`. The divergence is stated in the
text, not left for an operator to discover after a reboot. The paths table
gains `/usr/share/licenses/kydns/LICENSE`.

## Known gaps

**SELinux is not proven.** A privileged container does not meaningfully enforce
SELinux, so "works on Fedora with SELinux enforcing" stays untested by this
work. It is likely to work — `StateDirectory` yields `var_lib_t`, and an
unconfined system service retains `CAP_NET_BIND_SERVICE` — but likely is not
tested, and the README will not claim it. Closing this needs a real VM leg,
which is deferred as its own piece of work.

**Container systemd weakens what "in force" means.** `systemctl show` proves
the sandboxing directives are parsed and applied to the unit, which is exactly
what the deb leg proves. It does not prove the kernel-level confinement a
`ProtectSystem=strict` service gets on bare metal. This limitation applies
equally to the existing deb job and is not a regression.

**Only three of four container legs run.** Rocky 9 on arm64 is not tested. The
gap is the combination, not either axis; both are covered independently.

## Out of scope

| Thing | Why |
|---|---|
| yum/dnf repository | Same reasoning as the apt repository: hosting, signing, and a key-distribution story. |
| rpm GPG signing | Attestation covers provenance without key custody. Revisit with the repository. |
| openSUSE | A third user-creation and packaging convention for the smallest slice of the audience. |
| EPEL or Fedora submission | Would make the preset decision binding rather than chosen, and adds a review process. |
| SELinux policy module | Nothing indicates one is needed. Add if the VM leg proves otherwise. |
| armv6/armv7 | Unchanged from the packaging spec. |
