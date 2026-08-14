# RPM Packaging Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a `.rpm` for Fedora and the RHEL 9/10 family alongside the existing `.deb`, proven on real systemd rather than by manifest inspection alone.

**Architecture:** `nfpm` already emits a valid rpm from the current config; the work is a per-format licence path, a separate set of rpm maintainer scriptlets that follow systemd presets, one verifier that asserts the same contract through two backends, and a container-based behavioural suite that mirrors what the deb job proves. The deb's four maintainer scripts are not touched.

**Tech Stack:** GNU make, `go tool nfpm`, POSIX `sh` scriptlets, Docker with systemd as PID 1, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-08-14-kydns-rpm-packaging-design.md`

## Global Constraints

- **Never modify** `packaging/preinst.sh`, `packaging/postinst.sh`, `packaging/prerm.sh`, `packaging/postrm.sh`. The deb is shipped and tested; this change carries zero regression risk for it.
- Scriptlets are POSIX `sh`, `#!/bin/sh`, `set -e`. No bashisms.
- rpm argument convention: `$1` is `1` on first install, `2` on upgrade, `0` on final uninstall. dpkg's `configure` string never appears.
- The rpm is **not enabled** on install. It runs `systemctl preset`. This diverges from the deb on purpose.
- Version mapping: rpm forbids `-`, and nfpm rewrites it to `~`. `0.0.0-ci` becomes `0.0.0~ci`. Filenames must agree with package metadata.
- Arch mapping: `amd64` → `x86_64`, `arm64` → `aarch64`.
- Licence path: deb `/usr/share/doc/kydns/copyright`, rpm `/usr/share/licenses/kydns/LICENSE` with `type: license`.
- `/var/lib/kydns` is never in `contents` and is never removed by any scriptlet.
- Makefile recipes use **tabs**, and every line of a `for` loop body ends `|| exit 1` per the existing style.
- `make package` starts with `rm -rf dist`. Two packages that must coexist have to be copied out of `dist` between builds.

---

### Task 1: Build the rpm and verify it statically

**Files:**
- Modify: `Makefile` (the `package` target, and a new `RPMVERSION` variable near `VERSION ?= 0.0.0-dev`)
- Modify: `nfpm.yaml:47-56` (the `LICENSE` content entry)
- Modify: `scripts/verify-package.sh` (whole-file restructure into two backends)

**Interfaces:**
- Consumes: nothing.
- Produces: `scripts/verify-package.sh <package-path> <go-arch>` — dispatches on the file extension, exits 0 on success, 1 on a failed assertion, 2 when the required query tool is absent. `make package` writes `dist/kydns-<rpmversion>-1.<rpmarch>.rpm` in addition to the existing `.deb`.

- [ ] **Step 1: Write the failing test — restructure the verifier with an rpm backend**

Replace the whole of `scripts/verify-package.sh` with this. Both backends normalise their listing to `mode path` lines so one set of assertions covers both formats.

```sh
#!/bin/sh
# Static assertions on a built package: the manifest, the modes, the metadata.
# Runtime behaviour is checked separately by the CI smoke tests.
#
# usage: scripts/verify-package.sh <package-path> <expected-arch>
#
# <expected-arch> is always the Go arch (amd64, arm64). The rpm backend maps
# it to the name rpm uses.
set -eu

pkg=$1
arch=$2
fail=0

note() {
	echo "$1"
	fail=1
}

# Both backends fill these, so the assertions below are format-agnostic:
#   contents  — one "mode /absolute/path" line per file
#   deps      — one dependency per line
#   pkgarch   — the architecture as the package records it
#   conffiles — one config-file path per line
#   scripts   — the maintainer scripts, one name per line
#   licpath   — where this format expects the licence text

case "$pkg" in
*.deb)
	command -v dpkg-deb >/dev/null 2>&1 || {
		echo "dpkg-deb is required to verify a .deb"; exit 2; }

	# dpkg-deb prints paths as ./usr/bin/kydns; strip the leading dot so the
	# rpm backend's absolute paths can share the same assertions.
	contents=$(dpkg-deb -c "$pkg" | awk '{ p=$NF; sub(/^\./, "", p); print $1, p }')
	info=$(dpkg-deb -I "$pkg")
	deps=$(printf '%s\n' "$info" | sed -n 's/^ *Depends: *//p' | tr ',' '\n' | sed 's/^ *//; s/ .*//')
	pkgarch=$(printf '%s\n' "$info" | sed -n 's/^ *Architecture: *//p')
	conffiles=$(dpkg-deb -I "$pkg" conffiles 2>/dev/null || true)
	scripts=$(for s in preinst postinst prerm postrm; do
		dpkg-deb -I "$pkg" "$s" >/dev/null 2>&1 && echo "$s"
	done)
	wantarch=$arch
	wantscripts="preinst postinst prerm postrm"
	licpath=/usr/share/doc/kydns/copyright

	# The deb must not have picked up the rpm's preset logic.
	if dpkg-deb -I "$pkg" postinst 2>/dev/null | grep -q 'systemctl preset'; then
		note "WRONG: the deb carries the rpm's preset scriptlet"
	fi
	;;
*.rpm)
	command -v rpm >/dev/null 2>&1 || {
		echo "rpm is required to verify a .rpm (apt-get install rpm)"; exit 2; }

	contents=$(rpm -qlvp "$pkg" | awk '{ print $1, $NF }')
	deps=$(rpm -qp --requires "$pkg" | sed 's/ .*//')
	pkgarch=$(rpm -qp --qf '%{ARCH}' "$pkg")
	conffiles=$(rpm -qp --configfiles "$pkg")
	scripts=$(rpm -qp --scripts "$pkg" | sed -n 's/^\([a-z]*\) scriptlet.*/\1/p')
	case "$arch" in
	amd64) wantarch=x86_64 ;;
	arm64) wantarch=aarch64 ;;
	*) echo "no rpm arch known for $arch"; exit 2 ;;
	esac
	wantscripts="preinstall postinstall preuninstall postuninstall"
	licpath=/usr/share/licenses/kydns/LICENSE

	# The licence has to carry rpm's %license flag, not just live at the
	# right path, or `rpm -qL` and the doc-stripping tools ignore it.
	rpm -qp --qf '[%{FILENAMES} %{FILEFLAGS:fflags}\n]' "$pkg" |
		grep -q "^$licpath l$" ||
		note "MISSING: $licpath is not marked as a licence"

	# The deb's postinst is gated on dpkg's "configure" argument, which rpm
	# never passes. If it is in here, every install is a silent no-op.
	if rpm -qp --scripts "$pkg" | grep -q '"configure"'; then
		note "WRONG: the rpm carries the deb's postinst; it would never run"
	fi
	;;
*)
	echo "unknown package format: $pkg"
	exit 2
	;;
esac

check() {
	printf '%s\n' "$contents" | grep -qE -- "$1" || note "MISSING: $2"
}

check '^-rwxr-xr-x /usr/bin/kydns$' '/usr/bin/kydns mode 0755'
check '^-rw-r--r-- /lib/systemd/system/kydns\.service$' 'the systemd unit, mode 0644'
check '^-rw-r--r-- /etc/kydns/kydns\.yaml$' '/etc/kydns/kydns.yaml mode 0644'
check '/usr/share/doc/kydns/kydns\.example\.yaml$' 'the example config'
check "^-rw-r--r-- $licpath\$" "the AGPL text at $licpath"

# /var/lib/kydns must NOT be in the package. systemd creates it, and the
# package manager must never learn it owns it — that is what keeps a removal
# from deleting the database.
if printf '%s\n' "$contents" | grep -q ' /var/lib/kydns'; then
	note "PRESENT BUT MUST NOT BE: /var/lib/kydns is owned by the package"
fi

printf '%s\n' "$deps" | grep -qx 'ca-certificates' ||
	note "MISSING: a dependency on ca-certificates"

test "$pkgarch" = "$wantarch" ||
	note "WRONG: architecture is $pkgarch, wanted $wantarch"

printf '%s\n' "$conffiles" | grep -qx '/etc/kydns/kydns.yaml' ||
	note "MISSING: /etc/kydns/kydns.yaml is not registered as a config file"

for want in $wantscripts; do
	printf '%s\n' "$scripts" | grep -qx "$want" ||
		note "MISSING: maintainer script $want"
done

if [ "$fail" -eq 0 ]; then
	echo "OK: $pkg"
fi
exit "$fail"
```

- [ ] **Step 2: Run it against the existing deb to prove the restructure did not regress it**

```bash
make package VERSION=0.0.0-test ARCHES=amd64
./scripts/verify-package.sh dist/kydns_0.0.0-test_amd64.deb amd64
```

Expected: `OK: dist/kydns_0.0.0-test_amd64.deb`. If any assertion fires, the normalisation is wrong — fix it before going further, because the deb is the known-good reference.

- [ ] **Step 3: Run it against an rpm to watch it fail**

```bash
ARCH=amd64 VERSION=0.0.0-test go tool nfpm package -f nfpm.yaml -p rpm -t /tmp/probe.rpm
./scripts/verify-package.sh /tmp/probe.rpm amd64
```

Expected: FAIL with exactly three lines —

```
MISSING: /usr/share/licenses/kydns/LICENSE is not marked as a licence
MISSING: the AGPL text at /usr/share/licenses/kydns/LICENSE
WRONG: the rpm carries the deb's postinst; it would never run
```

No `MISSING: maintainer script` lines appear: nfpm's top-level `scripts:` block applies to every packager, so all four scriptlets are already embedded — they are just the deb's, which is what the third line catches. Task 2 fixes that; this task fixes the licence.

If `rpm` is not installed locally the script exits 2 with a message. On Debian or Ubuntu: `sudo apt-get install -y rpm`. On Arch or CachyOS the package is also `rpm-tools`; if neither is available, run this step inside `docker run --rm -v /tmp/probe.rpm:/p.rpm:ro fedora:latest` instead.

- [ ] **Step 4: Split the licence entry in `nfpm.yaml`**

Replace the single `LICENSE` entry at `nfpm.yaml:47-56` with both of these:

```yaml
  # The `license:` key above is dropped for deb — Debian control has no License
  # field, it is rpm-only. Without this the .deb would convey KyDNS with no
  # licence text at all, which Policy forbids and the AGPL does not allow.
  - src: LICENSE
    dst: /usr/share/doc/kydns/copyright
    packager: deb
    file_info:
      mode: 0644

  # rpm has the License field, set above, and its own place for the text.
  # `type: license` is what sets the flag `rpm -qL` reads.
  - src: LICENSE
    dst: /usr/share/licenses/kydns/LICENSE
    type: license
    packager: rpm
    file_info:
      mode: 0644
```

- [ ] **Step 5: Teach the Makefile to build the rpm**

Add below `VERSION ?= 0.0.0-dev`:

```make
# rpm forbids "-" in a version and nfpm rewrites it to "~", so the file name
# has to be built from the same substitution or it disagrees with the metadata
# inside the package.
RPMVERSION = $(subst -,~,$(VERSION))
```

Replace the `package` target with:

```make
package: dist
	for arch in $(ARCHES); do \
		ARCH=$$arch VERSION=$(VERSION) \
			go tool nfpm package -f nfpm.yaml -p deb \
				-t $(DIST)/kydns_$(VERSION)_$$arch.deb || exit 1; \
		case $$arch in \
		amd64) rpmarch=x86_64 ;; \
		arm64) rpmarch=aarch64 ;; \
		*) echo "no rpm arch known for $$arch"; exit 1 ;; \
		esac; \
		ARCH=$$arch VERSION=$(VERSION) \
			go tool nfpm package -f nfpm.yaml -p rpm \
				-t $(DIST)/kydns-$(RPMVERSION)-1.$$rpmarch.rpm || exit 1; \
	done
```

- [ ] **Step 6: Run both verifications**

```bash
make package VERSION=0.0.0-test ARCHES=amd64
./scripts/verify-package.sh dist/kydns_0.0.0-test_amd64.deb amd64
./scripts/verify-package.sh dist/kydns-0.0.0~test-1.x86_64.rpm amd64
```

Expected: the deb prints `OK`. The rpm now passes the licence assertions and fails on exactly one line, `WRONG: the rpm carries the deb's postinst; it would never run`, which Task 2 fixes. Confirm nothing else fails.

- [ ] **Step 7: Commit**

```bash
git add Makefile nfpm.yaml scripts/verify-package.sh
git commit -m "build: emit an rpm, and verify either format with one script

The contract is the same for both — same paths, same modes, same dependency,
same config-file registration, same absence of /var/lib/kydns — so one script
asserts it through two backends rather than two scripts drifting apart.

The licence is the one file that genuinely differs. Debian has no License
control field and needs the text at /usr/share/doc/kydns/copyright; rpm sets
the field and wants the text flagged at /usr/share/licenses/kydns/LICENSE."
```

---

### Task 2: rpm maintainer scriptlets

**Files:**
- Create: `packaging/rpm/preinstall.sh`
- Create: `packaging/rpm/postinstall.sh`
- Create: `packaging/rpm/preuninstall.sh`
- Create: `packaging/rpm/postuninstall.sh`
- Modify: `nfpm.yaml` (move the `scripts:` block under `overrides:`)

**Interfaces:**
- Consumes: `scripts/verify-package.sh` from Task 1, which already asserts all four scriptlets are present and that the deb's `postinst` is absent.
- Produces: an rpm whose scriptlets follow rpm's argument convention. Task 3's behavioural suite depends on `postinstall.sh` running `systemctl preset` (leaving the unit disabled) and on `preuninstall.sh` disabling on uninstall only.

- [ ] **Step 1: Run the verifier to confirm the tests are still failing**

```bash
./scripts/verify-package.sh dist/kydns-0.0.0~test-1.x86_64.rpm amd64
```

Expected: FAIL with the single line `WRONG: the rpm carries the deb's postinst; it would never run`.

- [ ] **Step 2: Write `packaging/rpm/preinstall.sh`**

```sh
#!/bin/sh
set -e

# A fixed system user, not systemd's DynamicUser: a transient UID would leave
# /var/lib/kydns owned by a number that means nothing during an incident.
id -u kydns >/dev/null 2>&1 || \
	useradd --system --user-group --no-create-home \
		--shell /usr/sbin/nologin kydns
```

- [ ] **Step 3: Write `packaging/rpm/postinstall.sh`**

```sh
#!/bin/sh
set -e

systemctl daemon-reload >/dev/null 2>&1 || true

# rpm passes 1 on a first install and 2 on an upgrade.
if [ "$1" = "1" ]; then
	# Presets, not a bare enable. On this family the host decides whether a
	# newly installed service starts at boot, and a package that enables
	# itself overrides a choice the sysadmin may have made deliberately.
	# The deb does the opposite, following Debian's convention.
	systemctl preset kydns.service >/dev/null 2>&1 || true

	cat <<'EOF'

KyDNS is installed. It is not running, and not enabled at boot.

Check that nothing else holds port 53:

  sudo ss -lnup 'sport = :53'

then enable and start it:

  sudo systemctl enable --now kydns

Read the one-time setup token and open the web UI:

  sudo cat /var/lib/kydns/setup-token
  ssh -L 8053:127.0.0.1:8053 <this-host>   # the UI is loopback-only
  http://127.0.0.1:8053/setup

EOF
fi

# The new binary is on disk but the old one is still running, so an upgrade
# would otherwise leave the security fix it carried unapplied. try-restart is
# a no-op on a stopped unit, which keeps a first install not-running.
systemctl try-restart kydns.service >/dev/null 2>&1 || true
```

- [ ] **Step 4: Write `packaging/rpm/preuninstall.sh`**

```sh
#!/bin/sh
set -e

# rpm passes 0 on the last uninstall and 1 on an upgrade. Stopping on an
# upgrade would leave the service down; postinstall restarts it instead.
#
# Disabling here is safe in a way it is not for dpkg: rpm keeps no
# config-files state for a later reinstall to misread.
if [ "$1" = "0" ]; then
	systemctl --no-reload disable --now kydns.service >/dev/null 2>&1 || true
fi
```

- [ ] **Step 5: Write `packaging/rpm/postuninstall.sh`**

```sh
#!/bin/sh
set -e

systemctl daemon-reload >/dev/null 2>&1 || true

# Kept on purpose. This directory is the entire registry and every credential
# KyDNS holds; removing a package must not be able to destroy it. The kydns
# user is kept too, because it still owns these files.
#
# The $1 test is what keeps an upgrade — postuninstall with 1 — from telling
# an operator their data was left behind by a removal that never happened.
if [ "$1" = "0" ] && [ -d /var/lib/kydns ]; then
	cat <<'EOF'

KyDNS data was left in /var/lib/kydns. It holds the registry database and
every credential, so removing the package does not remove it. Delete it
yourself once you are certain you no longer need it:

  sudo rm -rf /var/lib/kydns
  sudo userdel kydns

EOF
fi
```

- [ ] **Step 6: Make all four executable**

```bash
chmod +x packaging/rpm/*.sh
```

- [ ] **Step 7: Wire them up in `nfpm.yaml`**

Replace the trailing `scripts:` block with:

```yaml
# The two formats run different state machines, not the same one by different
# means: dpkg gets deb-systemd-helper, mask-instead-of-disable, and enable on
# install; rpm gets presets and disable on uninstall. One file holding both
# would leave half of every script unreachable on any given host.
overrides:
  deb:
    scripts:
      preinstall: packaging/preinst.sh
      postinstall: packaging/postinst.sh
      preremove: packaging/prerm.sh
      postremove: packaging/postrm.sh
  rpm:
    scripts:
      preinstall: packaging/rpm/preinstall.sh
      postinstall: packaging/rpm/postinstall.sh
      preremove: packaging/rpm/preuninstall.sh
      postremove: packaging/rpm/postuninstall.sh
```

- [ ] **Step 8: Rebuild and verify both formats pass**

```bash
make package VERSION=0.0.0-test ARCHES=amd64
./scripts/verify-package.sh dist/kydns_0.0.0-test_amd64.deb amd64
./scripts/verify-package.sh dist/kydns-0.0.0~test-1.x86_64.rpm amd64
```

Expected: `OK` for both. The deb must still pass — its scripts moved under `overrides` and a mistake there would drop them silently.

- [ ] **Step 9: Commit**

```bash
git add packaging/rpm nfpm.yaml
git commit -m "package: rpm scriptlets that follow rpm's conventions

The deb's postinst is gated on dpkg's 'configure' argument, which rpm never
passes, so shipping it in an rpm made every install a silent no-op: never
enabled, never restarted on upgrade, no setup banner.

Enablement follows systemd presets here rather than the deb's unconditional
enable. The banner says so, since an operator who starts it by hand and
reboots would otherwise lose DNS.

postuninstall's data notice is gated on the uninstall argument, so an upgrade
no longer claims data was left behind by a removal that never happened."
```

---

### Task 3: Behavioural suite — install, enable, serve

**Files:**
- Create: `scripts/rpm-test/Dockerfile`
- Create: `scripts/rpm-test/run.sh`

**Interfaces:**
- Consumes: an rpm built by `make package` and passing Task 1's verifier.
- Produces: `scripts/rpm-test/run.sh <base-image> <rpm> <upgrade-rpm>` — builds the test image, boots systemd, runs every assertion, prints the unit's journal on failure, and always removes the container. Exit 0 means the package behaves. Task 4 extends the same script; Task 5 calls it from CI.

- [ ] **Step 1: Write the test container**

`scripts/rpm-test/Dockerfile`. The base images ship no systemd, and this package's entire contract is systemd behaviour, so there is nothing to test without it.

```dockerfile
# The base images carry no systemd, and every claim this package makes is a
# systemd claim — enabled or not, running as kydns, bound to a privileged
# port, sandboxed by the unit's directives. So the test host installs one.
ARG BASE=fedora:latest
FROM ${BASE}

RUN dnf -y install systemd iproute bind-utils curl procps-ng \
	&& dnf clean all

# Nothing in a test container wants a getty, and remounting / fails in one.
RUN systemctl mask getty.target systemd-remount-fs.service

# systemd's shutdown signal, so `docker stop` is not a 10-second wait.
STOPSIGNAL SIGRTMIN+3
CMD ["/usr/sbin/init"]
```

- [ ] **Step 2: Write the harness with its first assertions**

`scripts/rpm-test/run.sh`. Written as a script rather than inline workflow YAML so it can be run on a laptop, which is how it will be debugged.

```sh
#!/bin/sh
# Proves a built .rpm against a real systemd, the way ci.yml proves the .deb.
#
#   usage: scripts/rpm-test/run.sh <base-image> <rpm> <upgrade-rpm>
#
#   make package VERSION=0.0.0-test ARCHES=amd64
#   cp dist/kydns-0.0.0~test-1.x86_64.rpm /tmp/base.rpm
#   echo '# upgrade marker: the shipped template changed' >> kydns.package.yaml
#   make package VERSION=9.9.9-upgrade ARCHES=amd64
#   git checkout -- kydns.package.yaml
#   cp dist/kydns-9.9.9~upgrade-1.x86_64.rpm /tmp/upgrade.rpm
#   scripts/rpm-test/run.sh fedora:latest /tmp/base.rpm /tmp/upgrade.rpm
set -eu

base=$1
rpm_pkg=$(readlink -f "$2")
upgrade_pkg=$(readlink -f "$3")
name=kydns-rpm-test-$$
here=$(dirname "$0")

cleanup() {
	status=$?
	if [ "$status" -ne 0 ]; then
		echo "--- kydns journal ---"
		docker exec "$name" journalctl -u kydns --no-pager -n 200 2>&1 || true
	fi
	docker rm -f "$name" >/dev/null 2>&1 || true
	exit "$status"
}
trap cleanup EXIT

docker build --build-arg "BASE=$base" -t "kydns-rpm-test:$base" "$here"

# --privileged and the cgroup mount are what let systemd run as PID 1. This
# is a test host, not a deployment shape.
docker run -d --name "$name" --privileged --cgroupns=host \
	-v /sys/fs/cgroup:/sys/fs/cgroup:rw \
	-v "$rpm_pkg":/pkgs/base.rpm:ro \
	-v "$upgrade_pkg":/pkgs/upgrade.rpm:ro \
	"kydns-rpm-test:$base" >/dev/null

# Run a block of shell inside the container, tracing it so a failure shows
# which line failed.
in_container() {
	docker exec "$name" sh -eux -c "$1"
}

echo "== waiting for systemd"
booted=no
i=0
while [ "$i" -lt 60 ]; do
	state=$(docker exec "$name" systemctl is-system-running 2>/dev/null || true)
	case "$state" in
	running | degraded) booted=yes; break ;;
	esac
	i=$((i + 1))
	sleep 1
done
test "$booted" = yes || { echo "systemd never came up in the container"; exit 1; }

echo "== installs"
in_container '
	dnf -y install /pkgs/base.rpm
	test -x /usr/bin/kydns
	/usr/bin/kydns version
'

echo "== presets leave it disabled and stopped"
in_container '
	if systemctl is-enabled kydns >/dev/null 2>&1; then
		echo "install enabled the unit; presets should have left that to the host"
		exit 1
	fi
	if systemctl is-active --quiet kydns; then
		echo "install started kydns unasked"
		exit 1
	fi
'

# A container has no systemd-resolved, but 127.0.0.2:53 keeps parity with the
# deb job and is still a privileged port, which is the part being proven.
echo "== configure for the container"
in_container '
	cat > /etc/kydns/kydns.yaml <<YAML
data_dir: /var/lib/kydns
dns:
  listen: "127.0.0.2:53"
  allow_query: ["127.0.0.0/8"]
admin:
  listen: "127.0.0.1:8053"
YAML
'

echo "== enable --now brings it up"
in_container '
	systemctl enable --now kydns
	systemctl is-enabled kydns
	i=0
	while [ $i -lt 60 ]; do
		curl -sf http://127.0.0.1:8053/api/v1/healthz && break
		i=$((i + 1))
		sleep 1
	done
	systemctl is-active kydns
'

echo "== runs as a non-root user"
in_container '
	pid=$(systemctl show -p MainPID --value kydns)
	uid=$(awk "/^Uid:/{print \$2}" /proc/$pid/status)
	test "$uid" != "0" || { echo "kydns is running as root"; exit 1; }
	test "$(id -nu "$uid")" = "kydns"
'

echo "== state directory is locked down"
in_container '
	test "$(stat -c "%a %U" /var/lib/kydns)" = "700 kydns"
	test "$(stat -c "%a" /var/lib/kydns/setup-token)" = "600"
	test "$(stat -c "%a" /var/lib/kydns/bootstrap-token)" = "600"
'

# systemctl show renders these in its own normalized form, not the unit
# file's spelling, so assert against that form. A systemd version that
# silently ignores one, or a future edit that drops it, fails here.
echo "== hardening is in force"
in_container '
	systemd-analyze security kydns.service || true

	assert_show() {
		got=$(systemctl show -p "$1" --value kydns)
		test "$got" = "$2" || {
			echo "kydns.service $1=$got, wanted $2"; exit 1; }
	}

	assert_show User kydns
	assert_show AmbientCapabilities cap_net_bind_service
	assert_show CapabilityBoundingSet cap_net_bind_service
	assert_show NoNewPrivileges yes
	assert_show ProtectSystem strict
'

echo "== serves DNS on a privileged port"
in_container '
	token=$(cat /var/lib/kydns/bootstrap-token)
	curl -sf -X POST -H "Authorization: Bearer $token" \
		-H "Content-Type: application/json" \
		-d "{\"name\":\"ci\",\"addresses\":[{\"address\":\"192.168.1.20\"}]}" \
		http://127.0.0.1:8053/api/v1/services
	answer=$(dig @127.0.0.2 -p 53 ci.home.arpa A +short)
	test "$answer" = "192.168.1.20" || {
		echo "resolved \"$answer\", wanted 192.168.1.20"; exit 1; }
'

echo "OK: $rpm_pkg behaves on $base"
```

- [ ] **Step 3: Make it executable and run it**

```bash
chmod +x scripts/rpm-test/run.sh
make package VERSION=0.0.0-test ARCHES=amd64
cp dist/kydns-0.0.0~test-1.x86_64.rpm /tmp/base.rpm
cp /tmp/base.rpm /tmp/upgrade.rpm
./scripts/rpm-test/run.sh fedora:latest /tmp/base.rpm /tmp/upgrade.rpm
```

Expected: every `==` banner prints, then `OK: /tmp/base.rpm behaves on fedora:latest`. The upgrade package is a placeholder here — Task 4 is what uses it.

If the container never reaches `running` or `degraded`, the cgroup mount is the usual cause; confirm the host is cgroup v2 with `stat -fc %T /sys/fs/cgroup` returning `cgroup2fs`.

- [ ] **Step 4: Run it against Rocky 9 too**

```bash
./scripts/rpm-test/run.sh rockylinux:9 /tmp/base.rpm /tmp/upgrade.rpm
```

Expected: the same `OK`. This is the leg most likely to surface a hardening directive its older systemd ignores — if `assert_show` fails here, that is a real finding about the unit file, not a test bug. Report it rather than weakening the assertion.

- [ ] **Step 5: Commit**

```bash
git add scripts/rpm-test
git commit -m "test(package): prove the rpm on a real systemd

A manifest check cannot see the thing most likely to break: whether the
scriptlets did anything. The deb is proven by installing it and watching the
service run, and the rpm now gets the same treatment.

Written as a script rather than inline workflow YAML because that is how it
will be debugged — on a laptop, against one base image at a time.

Presets mean the assertion inverts: the unit must come out disabled, and
enable --now must bring it up."
```

---

### Task 4: Behavioural suite — upgrade and removal

**Files:**
- Modify: `scripts/rpm-test/run.sh` (append two blocks before the final `echo "OK: ..."`)

**Interfaces:**
- Consumes: `run.sh` from Task 3, and its third argument, which must now be an rpm built from a genuinely different config template.
- Produces: nothing new; the same script, covering the upgrade and removal paths.

- [ ] **Step 1: Build a real upgrade package**

A byte-identical template never enters rpm's modified-config path, so the upgrade must actually differ.

```bash
cp dist/kydns-0.0.0~test-1.x86_64.rpm /tmp/base.rpm
echo '# upgrade marker: the shipped template changed' >> kydns.package.yaml
make package VERSION=9.9.9-upgrade ARCHES=amd64
git checkout -- kydns.package.yaml
cp dist/kydns-9.9.9~upgrade-1.x86_64.rpm /tmp/upgrade.rpm
```

Note `make package` runs `rm -rf dist` first, which is why the base package is copied out before the second build.

- [ ] **Step 2: Write the failing test — append the upgrade block**

Insert immediately before the closing `echo "OK: $rpm_pkg behaves on $base"`:

```sh
# The whole check is one shell invocation because it compares timestamps
# taken before and after the upgrade.
echo "== an operator's config edits survive an upgrade"
in_container '
	echo "# operator edit, must survive" >> /etc/kydns/kydns.yaml
	started_before=$(systemctl show -p ExecMainStartTimestamp --value kydns)

	dnf -y upgrade /pkgs/upgrade.rpm

	grep -q "operator edit, must survive" /etc/kydns/kydns.yaml || {
		echo "the upgrade clobbered the operator config"; exit 1; }
	grep -q "127.0.0.2:53" /etc/kydns/kydns.yaml
	if grep -q "upgrade marker" /etc/kydns/kydns.yaml; then
		echo "noreplace did not hold; the shipped template replaced the live one"
		exit 1
	fi
	# rpm only writes .rpmnew when the templates really differ, so this is
	# what proves the modified-config path was exercised at all.
	grep -q "upgrade marker" /etc/kydns/kydns.yaml.rpmnew || {
		echo "no .rpmnew: the upgrade never hit the config path"; exit 1; }

	# An upgrade must actually replace the running process, or a security fix
	# ships to disk and never runs.
	systemctl is-active kydns
	started_after=$(systemctl show -p ExecMainStartTimestamp --value kydns)
	if [ -z "$started_after" ] || [ "$started_after" = "$started_before" ]; then
		echo "the upgrade left the old process running: $started_before"
		exit 1
	fi
'

echo "== removal keeps the data"
in_container '
	dnf -y remove kydns

	if systemctl is-active --quiet kydns; then
		echo "removal left kydns running"; exit 1
	fi
	test ! -f /usr/bin/kydns || { echo "removal left the binary"; exit 1; }

	# This directory is 0700 kydns; every check needs to be root or a
	# surviving file reads as a missing one.
	ls -la /var/lib/kydns
	test -d /var/lib/kydns || { echo "removal destroyed the registry"; exit 1; }
	test -f /var/lib/kydns/kydns.db || {
		echo "removal destroyed the database"; exit 1; }
'
```

- [ ] **Step 3: Run it with a placeholder upgrade to watch the new block fail**

```bash
./scripts/rpm-test/run.sh fedora:latest /tmp/base.rpm /tmp/base.rpm
```

Expected: FAIL at `== an operator's config edits survive an upgrade` with `no .rpmnew: the upgrade never hit the config path` — passing the same package twice is exactly the byte-identical case that proves nothing. This failure confirms the assertion has teeth.

- [ ] **Step 4: Run it with the real upgrade package**

```bash
./scripts/rpm-test/run.sh fedora:latest /tmp/base.rpm /tmp/upgrade.rpm
./scripts/rpm-test/run.sh rockylinux:9 /tmp/base.rpm /tmp/upgrade.rpm
```

Expected: both print `OK`.

- [ ] **Step 5: Commit**

```bash
git add scripts/rpm-test/run.sh
git commit -m "test(package): cover the rpm upgrade and removal paths

The upgrade only matters when the shipped template also changed — that is
the only case that enters rpm's modified-config path, and passing the same
package twice proves nothing. The .rpmnew assertion is what detects the
difference.

Removal keeps /var/lib/kydns. rpm has no purge, so this is the whole
removal story, and it is the one that must never take the database."
```

---

### Task 5: CI job

**Files:**
- Modify: `.github/workflows/ci.yml` (append a `package-rpm` job after the existing `package` job, which ends at line 400)

**Interfaces:**
- Consumes: `make package`, `scripts/verify-package.sh`, `scripts/rpm-test/run.sh`.
- Produces: nothing consumed by later tasks.

- [ ] **Step 1: Append the job**

```yaml
  # Proves the rpm the way the deb job proves the deb: on a real systemd, not
  # by reading the manifest. Distribution varies the systemd version and
  # architecture varies the binary, so each axis is covered once rather than
  # paying for the full matrix.
  package-rpm:
    strategy:
      fail-fast: false
      matrix:
        include:
          - runner: ubuntu-latest
            arch: amd64
            rpmarch: x86_64
            base: fedora:latest
          - runner: ubuntu-24.04-arm
            arch: arm64
            rpmarch: aarch64
            base: fedora:latest
          # Rocky 9's older systemd is where a hardening directive is most
          # likely to be silently ignored.
          - runner: ubuntu-latest
            arch: amd64
            rpmarch: x86_64
            base: rockylinux:9
    runs-on: ${{ matrix.runner }}
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version-file: go.mod
          cache: true

      # `make package` starts by removing dist, so the first package is copied
      # out before the second is built.
      - name: build the package
        run: |
          set -eux
          make package VERSION=0.0.0-ci ARCHES=${{ matrix.arch }}
          mkdir -p /tmp/rpms
          cp dist/kydns-0.0.0~ci-1.${{ matrix.rpmarch }}.rpm /tmp/rpms/base.rpm

      # A byte-identical template never enters rpm's modified-config path, so
      # the upgrade package has to really differ.
      - name: build the upgrade package
        run: |
          set -eux
          echo "# upgrade marker: the shipped template changed" >> kydns.package.yaml
          make package VERSION=9.9.9-upgrade ARCHES=${{ matrix.arch }}
          git checkout -- kydns.package.yaml
          cp dist/kydns-9.9.9~upgrade-1.${{ matrix.rpmarch }}.rpm /tmp/rpms/upgrade.rpm

      - name: manifest is right
        run: |
          set -eux
          sudo apt-get update -qq
          sudo apt-get install -y -qq rpm
          ./scripts/verify-package.sh /tmp/rpms/base.rpm ${{ matrix.arch }}

      - name: behaves on ${{ matrix.base }}
        run: |
          ./scripts/rpm-test/run.sh ${{ matrix.base }} \
            /tmp/rpms/base.rpm /tmp/rpms/upgrade.rpm
```

- [ ] **Step 2: Check the workflow parses**

```bash
python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/ci.yml')); print('parses')"
```

Expected: `parses`. If `PyYAML` is missing, use `docker run --rm -v "$PWD":/w -w /w cytopia/yamllint .github/workflows/ci.yml` instead.

- [ ] **Step 3: Confirm the job list is what you expect**

```bash
python3 -c "import yaml; print(list(yaml.safe_load(open('.github/workflows/ci.yml'))['jobs']))"
```

Expected: `['test', 'build', 'docker', 'publish', 'package', 'package-rpm']`.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: prove the rpm on Fedora and Rocky 9

Three legs, not four. Distribution varies the systemd version and
architecture varies the binary; each axis is covered once, and Rocky 9 on
arm64 is the combination left untested.

The job is thin because the suite is a script: it can be run on a laptop
against one base image, which is where it will actually be debugged."
```

---

### Task 6: Release workflow

**Files:**
- Modify: `.github/workflows/release.yml:69-75` (verify), `:79-84` (checksums), `:88-91` (attestation), `:93-99` (artifact), `:104-113` (publish)

**Interfaces:**
- Consumes: `make package` and `scripts/verify-package.sh`.
- Produces: released `.rpm` assets, checksummed and attested alongside the debs.

- [ ] **Step 1: Verify the rpms too**

Replace the `manifests are right` step:

```yaml
      - name: manifests are right
        env:
          VERSION: ${{ steps.version.outputs.version }}
        run: |
          set -eux
          sudo apt-get update -qq
          sudo apt-get install -y -qq rpm
          ./scripts/verify-package.sh "dist/kydns_${VERSION}_amd64.deb" amd64
          ./scripts/verify-package.sh "dist/kydns_${VERSION}_arm64.deb" arm64
          # rpm forbids "-" in a version, so nfpm rewrites it to "~" and the
          # file name follows.
          rpmversion=${VERSION//-/\~}
          ./scripts/verify-package.sh "dist/kydns-${rpmversion}-1.x86_64.rpm" amd64
          ./scripts/verify-package.sh "dist/kydns-${rpmversion}-1.aarch64.rpm" arm64
```

- [ ] **Step 2: Add rpms to the checksums, attestation, artifact, and release**

Four one-line edits:

```yaml
          sha256sum *.tar.gz *.deb *.rpm > SHA256SUMS
```

```yaml
          subject-path: "dist/*.tar.gz, dist/*.deb, dist/*.rpm, dist/SHA256SUMS"
```

```yaml
          path: |
            dist/*.tar.gz
            dist/*.deb
            dist/*.rpm
            dist/SHA256SUMS
```

```yaml
            dist/*.tar.gz dist/*.deb dist/*.rpm dist/SHA256SUMS
```

- [ ] **Step 3: Check it parses and the version substitution is right**

```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/release.yml')); print('parses')"
bash -c 'VERSION=1.0.0-rc1; echo "${VERSION//-/\~}"'
```

Expected: `parses`, then `1.0.0~rc1`.

- [ ] **Step 4: Prove the whole release path locally**

```bash
make package VERSION=1.0.0-rc1
ls dist
./scripts/verify-package.sh dist/kydns-1.0.0~rc1-1.x86_64.rpm amd64
./scripts/verify-package.sh dist/kydns-1.0.0~rc1-1.aarch64.rpm arm64
./scripts/verify-package.sh dist/kydns_1.0.0-rc1_amd64.deb amd64
./scripts/verify-package.sh dist/kydns_1.0.0-rc1_arm64.deb arm64
```

Expected: four `OK` lines. This is the prerelease case where the deb and rpm version strings legitimately differ.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "release: publish the rpms with the debs

Checksummed and attested alongside everything else — the assets most likely
to be fetched by a script are the ones that most need provenance.

A prerelease tag ships two spellings on purpose: v1.0.0-rc1 becomes
1.0.0-rc1 as a deb and 1.0.0~rc1 as an rpm, because rpm forbids the hyphen
and orders the tilde below the release."
```

---

### Task 7: Document the rpm

**Files:**
- Modify: `README.md:385-435` (the "Install from a package" section)

**Interfaces:**
- Consumes: the released asset names from Task 6.
- Produces: nothing.

- [ ] **Step 1: Add the Fedora and RHEL block**

After the existing Debian block and its `gh attestation verify` example (`README.md:387-399`), insert:

```markdown
Fedora, and the RHEL 9 and 10 family including Rocky and Alma, on `x86_64`
and `aarch64`:

```sh
# pick the .rpm matching your architecture from the latest release
curl -LO https://github.com/yoshiofthewire/kydns-server/releases/latest/download/kydns-<version>-1.aarch64.rpm
sudo dnf install ./kydns-<version>-1.aarch64.rpm
gh attestation verify kydns-<version>-1.aarch64.rpm --repo yoshiofthewire/kydns-server
```
```

- [ ] **Step 2: Make the start instructions honest about the divergence**

Replace the paragraph at `README.md:401-407` with:

```markdown
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
```

- [ ] **Step 3: Add the licence path and correct the removal note**

In the paths table at `README.md:427-431`, add:

```markdown
| `/usr/share/doc/kydns/copyright`, `/usr/share/licenses/kydns/LICENSE` | The AGPL text, deb and rpm respectively. |
```

Replace the closing paragraph at `README.md:433-435` with:

```markdown
Removing the package leaves `/var/lib/kydns` in place — with `apt purge` and
with `dnf remove` alike. It holds your whole registry and every credential.
Delete it yourself when you are sure.
```

- [ ] **Step 4: Read the section back**

```bash
sed -n '385,450p' README.md
```

Expected: both install paths present, the enable-versus-start difference stated where an operator will see it before rebooting, and no remaining claim that the package is enabled on install without qualifying which package.

- [ ] **Step 5: Commit**

```bash
git add README.md
git commit -m "docs: install from the rpm

The two packages differ where an operator can get hurt: the deb is enabled
at boot, the rpm follows the host's presets and is not. Someone who installs
the rpm, starts it by hand, and reboots would otherwise lose DNS and have no
way to know why."
```

---

## Verification

After Task 7, the whole change is provable locally:

```bash
make package VERSION=0.0.0-test ARCHES=amd64
./scripts/verify-package.sh dist/kydns_0.0.0-test_amd64.deb amd64
./scripts/verify-package.sh dist/kydns-0.0.0~test-1.x86_64.rpm amd64
cp dist/kydns-0.0.0~test-1.x86_64.rpm /tmp/base.rpm
echo '# upgrade marker: the shipped template changed' >> kydns.package.yaml
make package VERSION=9.9.9-upgrade ARCHES=amd64
git checkout -- kydns.package.yaml
cp dist/kydns-9.9.9~upgrade-1.x86_64.rpm /tmp/upgrade.rpm
./scripts/rpm-test/run.sh fedora:latest /tmp/base.rpm /tmp/upgrade.rpm
./scripts/rpm-test/run.sh rockylinux:9 /tmp/base.rpm /tmp/upgrade.rpm
go test ./...
```

All of it must pass before the branch is offered for merge.

## What this plan does not do

Carried from the spec, so nobody has to re-derive them:

- **SELinux enforcing is untested.** A privileged container cannot prove it. Closing this needs a VM leg, deferred as separate work.
- **Rocky 9 on arm64 is untested.** Both axes are covered independently, the combination is not.
- **No rpm GPG signing and no yum/dnf repository.** Attestation covers provenance without key custody.
- **openSUSE is not supported.** A third user-creation and packaging convention.
