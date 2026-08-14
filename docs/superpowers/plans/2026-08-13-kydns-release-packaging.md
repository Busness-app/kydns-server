# Release Packaging Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish versioned KyDNS binaries and a Debian package from a tagged
release, verified by an install-and-run test on both amd64 and arm64.

**Architecture:** A `Makefile` target cross-compiles with `GOARCH` and drives
`nfpm` to assemble the `.deb`, so both CI workflows call the same build rather
than duplicating steps. `ci.yml` gains a package job that builds and smoke-tests
the package on every pull request; a new `release.yml` builds the same artifacts
on a `v*` tag, attests them, and uploads them to the GitHub Release.

**Tech Stack:** Go 1.26, `nfpm` v2 (pinned as a Go tool dependency), systemd,
GitHub Actions, `dpkg`.

**Spec:** `docs/superpowers/specs/2026-08-13-kydns-release-packaging-design.md`

## Global Constraints

- Go version comes from `go.mod` (currently `1.26.5`). Never hardcode it in a
  workflow; use `go-version-file: go.mod`.
- All binary builds use `CGO_ENABLED=0` and `-trimpath`. KyDNS uses the pure-Go
  SQLite driver and must run on a base with no libc.
- Architectures: `linux/amd64` and `linux/arm64` only.
- Package version must be a valid Debian version, which **must start with a
  digit**. Strip the leading `v` from tags: `v1.2.3` becomes `1.2.3`. The
  default when not building from a tag is `0.0.0-dev`.
- The service runs as the system user `kydns`, never root, with
  `CAP_NET_BIND_SERVICE` as its only capability.
- `/etc/kydns/kydns.yaml` is `config|noreplace`. An operator's edits survive an
  upgrade.
- `/var/lib/kydns` is never removed by the package, including on purge.
- Existing actions pinned in this repo: `actions/checkout@v4`,
  `actions/setup-go@v5`. Match those.
- License string: `AGPL-3.0-or-later`.
- Maintainer string: `Yoshi <yoshi@urlxl.com>`.

---

## File Structure

**Created:**

| File | Responsibility |
|---|---|
| `kydns.package.yaml` | The config baked into the `.deb` at `/etc/kydns/kydns.yaml`. |
| `packaging/kydns.service` | The systemd unit and all sandboxing. |
| `packaging/preinst.sh` | Creates the `kydns` system user. |
| `packaging/postinst.sh` | `daemon-reload`, enable, print next steps. |
| `packaging/prerm.sh` | Stop and disable, on removal only. |
| `packaging/postrm.sh` | `daemon-reload`, and tell the operator data was kept. |
| `nfpm.yaml` | Package metadata and file manifest. |
| `scripts/verify-package.sh` | Static assertions on a built `.deb`. |
| `.github/workflows/release.yml` | Tag-triggered build, attest, upload. |

**Modified:**

| File | Change |
|---|---|
| `cmd/kydns/main.go` | `version` variable, `version` subcommand, usage line. |
| `cmd/kydns/main_test.go` | Test for the `version` subcommand. |
| `internal/config/example_test.go` | Test that `kydns.package.yaml` loads. |
| `Dockerfile` | `ARG VERSION` threaded into `-ldflags`. |
| `Makefile` | `dist` and `package` targets. |
| `.github/workflows/ci.yml` | Version-injection check; `package` job; `VERSION` build-arg on publish. |
| `.gitignore` | Ignore `dist/`. |
| `README.md` | Install-from-package section. |

---

## Task 1: Version stamping

The binary has no version string today. Packages need one and so do bug
reports.

**Files:**
- Modify: `cmd/kydns/main.go`
- Modify: `cmd/kydns/main_test.go`
- Modify: `Dockerfile:9-19`
- Modify: `.github/workflows/ci.yml` (the `build` job, and `build-args` on `publish`)
- Test: `cmd/kydns/main_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `main.version` — a package-level `string` in `package main` at
  `cmd/kydns`, settable with `-ldflags "-X main.version=<v>"`. Every later task
  that builds a binary sets it.

- [ ] **Step 1: Write the failing test**

Add to `cmd/kydns/main_test.go`:

```go
func TestVersionCommandPrintsVersion(t *testing.T) {
	var out bytes.Buffer
	if code := run([]string{"version"}, &out); code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if got := strings.TrimSpace(out.String()); got != version {
		t.Errorf("output = %q, want %q", got, version)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/kydns/ -run TestVersionCommandPrintsVersion -v`
Expected: FAIL to compile — `undefined: version`.

- [ ] **Step 3: Add the variable, the usage line, and the switch case**

In `cmd/kydns/main.go`, add above `const usage`:

```go
// version is set at link time with -X main.version. "dev" means someone built
// straight from a source tree, which is exactly what a bug report needs to say.
var version = "dev"
```

Add to the `usage` string, after the `admin` line and before the closing
backtick:

```
  version   print the version
```

Add to the `switch` in `run`, before `default:`:

```go
	case "version":
		fmt.Fprintln(stdout, version)
		return 0
```

- [ ] **Step 4: Run the whole package's tests**

Run: `go test ./cmd/kydns/ -v`
Expected: PASS, including `TestEveryAdvertisedCommandRoutes/version` — that
existing test walks the usage text and will now cover the new command for free.

- [ ] **Step 5: Verify the link-time injection actually works**

Run:

```bash
go build -ldflags "-X main.version=1.2.3-test" -o /tmp/kydns-ver ./cmd/kydns
/tmp/kydns-ver version
```

Expected: prints `1.2.3-test`. If it prints `dev`, the `-X` path is wrong —
check that the symbol is `main.version` and that `version` is not `const`.

- [ ] **Step 6: Thread VERSION through the Dockerfile**

In `Dockerfile`, after the existing `ARG TARGETARCH` on line 18, add:

```dockerfile
ARG VERSION=dev
```

and change the build line to:

```dockerfile
RUN CGO_ENABLED=0 GOARCH=$TARGETARCH go build -trimpath \
    -ldflags="-s -w -X main.version=$VERSION" -o /out/kydns ./cmd/kydns
```

- [ ] **Step 7: Add the injection check and the build-arg to CI**

In `.github/workflows/ci.yml`, in the `build` job, replace the `build without
cgo` step's `run` with a version-injecting build and add an assertion after the
existing `binary runs` step:

```yaml
      - name: build without cgo
        env:
          CGO_ENABLED: "0"
        run: |
          go build -trimpath -ldflags "-X main.version=ci-test" \
            -o /tmp/kydns ./cmd/kydns

      - name: version is stamped at link time
        run: |
          got=$(/tmp/kydns version)
          test "$got" = "ci-test" || {
            echo "kydns version printed '$got', wanted 'ci-test'"; exit 1; }
```

In the `publish` job, add `build-args` to the `docker/build-push-action@v6`
step, alongside the existing `platforms` key:

```yaml
          build-args: |
            VERSION=${{ github.sha }}
```

- [ ] **Step 8: Confirm the docker build still works**

Run: `docker build --build-arg VERSION=9.9.9 -t kydns:vertest .`
Then: `docker run --rm kydns:vertest version`
Expected: prints `9.9.9`.

- [ ] **Step 9: Commit**

```bash
git add cmd/kydns/main.go cmd/kydns/main_test.go Dockerfile .github/workflows/ci.yml
git commit -m "feat: stamp a version into the binary at link time"
```

---

## Task 2: The packaged config

The `.deb` ships a working `/etc/kydns/kydns.yaml`, mirroring how the image
ships `kydns.docker.yaml`. Unlike the image, it must **not** expose the admin
interface.

**Files:**
- Create: `kydns.package.yaml`
- Modify: `internal/config/example_test.go`
- Test: `internal/config/example_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `kydns.package.yaml` at the repo root — the `src` for the
  `/etc/kydns/kydns.yaml` entry in Task 3's `nfpm.yaml`.

- [ ] **Step 1: Write the failing test**

Add to `internal/config/example_test.go`, after the `dockerPath` const:

```go
// packagePath is the config the .deb installs at /etc/kydns/kydns.yaml.
const packagePath = "../../kydns.package.yaml"

// The package's config is what a fresh `apt install` runs on. Unlike the
// image's, it must keep the admin listener on loopback: a host install has a
// real LAN address, and binding it would publish the admin UI to the network
// without the operator ever asking for that.
func TestPackageConfigLoads(t *testing.T) {
	c, err := Load(packagePath)
	if err != nil {
		t.Fatalf("kydns.package.yaml does not load: %v", err)
	}
	if c.DataDir != "/var/lib/kydns" {
		t.Errorf("data_dir is %q, want the unit's StateDirectory", c.DataDir)
	}
	if !strings.HasPrefix(c.Admin.Listen, "127.") && !strings.HasPrefix(c.Admin.Listen, "[::1]") {
		t.Errorf("admin.listen is %q; the package must not expose the admin UI", c.Admin.Listen)
	}
	if c.DNS.AllowTailscale {
		t.Error("package config ships with allow_tailscale on; the default must be closed")
	}
	if c.Discovery.DHCPLeaseFile != "" {
		t.Error("package config ships with discovery enabled; it must be opt-in")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/config/ -run TestPackageConfigLoads -v`
Expected: FAIL — `kydns.package.yaml does not load: read config: ... no such file`.

- [ ] **Step 3: Create the config**

Create `kydns.package.yaml`:

```yaml
# The configuration the .deb installs at /etc/kydns/kydns.yaml.
#
# It sets one thing: data_dir. The other two file-owned settings, dns.listen
# and admin.listen, are already right at their defaults for a host install.
#
# Everything else is left out on purpose. Those keys seed the database on the
# first run and are edited afterwards under Settings in the web UI, with
# `kydns settings set`, or over the API. See kydns.example.yaml for the
# defaults and the reasoning behind them.
#
# dpkg treats this file as a conffile: your edits survive an upgrade.

# Matches StateDirectory=kydns in the systemd unit. Holds kydns.db plus the
# setup and bootstrap tokens; back it up.
data_dir: /var/lib/kydns

# admin.listen stays at its default, 127.0.0.1:8053. KyDNS speaks plain HTTP,
# so reaching the web UI from another machine means either an SSH tunnel:
#
#   ssh -L 8053:127.0.0.1:8053 <this-host>
#
# or a TLS-terminating reverse proxy in front of it. Change this to
# "0.0.0.0:8053" only if you accept publishing an unencrypted admin UI to your
# LAN.
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/config/ -v`
Expected: PASS, including the existing `TestExampleConfigLoads` and
`TestDockerConfigLoads`.

- [ ] **Step 5: Commit**

```bash
git add kydns.package.yaml internal/config/example_test.go
git commit -m "feat: add the config the deb installs"
```

---

## Task 3: The package itself

The unit, the maintainer scripts, the `nfpm` manifest, the build targets, and a
script that asserts the built `.deb` contains what it should.

**Files:**
- Create: `packaging/kydns.service`
- Create: `packaging/preinst.sh`, `packaging/postinst.sh`, `packaging/prerm.sh`, `packaging/postrm.sh`
- Create: `nfpm.yaml`
- Create: `scripts/verify-package.sh`
- Modify: `Makefile`
- Modify: `.gitignore`
- Test: `scripts/verify-package.sh`

**Interfaces:**
- Consumes: `main.version` (Task 1), `kydns.package.yaml` (Task 2).
- Produces:
  - `make dist VERSION=<v>` — writes `dist/kydns_linux_<arch>/kydns` and
    `dist/kydns_<v>_linux_<arch>.tar.gz` for `amd64` and `arm64`.
  - `make package VERSION=<v>` — writes `dist/kydns_<v>_<arch>.deb`.
  - `scripts/verify-package.sh <deb-path> <arch>` — exits non-zero on any
    manifest violation.

- [ ] **Step 1: Pin nfpm as a Go tool dependency**

Run:

```bash
go get -tool github.com/goreleaser/nfpm/v2/cmd/nfpm
go mod tidy
go tool nfpm --version
```

Expected: prints an nfpm version. This pins the exact version in `go.mod`, so
CI does not fetch an unpinned tool at build time. Record the resolved version in
the commit message.

- [ ] **Step 2: Write the systemd unit**

Create `packaging/kydns.service`:

```ini
[Unit]
Description=KyDNS local DNS server and service directory
Documentation=https://github.com/yoshiofthewire/kydns-server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=kydns
Group=kydns
ExecStart=/usr/bin/kydns serve --config /etc/kydns/kydns.yaml
Restart=on-failure
RestartSec=5s

# Port 53 is the only privileged thing KyDNS does. It binds exactly two
# addresses, dns.listen and admin.listen, and nothing else.
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes

# The database and the first-run tokens. The only writable path.
StateDirectory=kydns
StateDirectoryMode=0700

ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SystemCallArchitectures=native
SystemCallFilter=@system-service
UMask=0077

[Install]
WantedBy=multi-user.target
```

`MemoryDenyWriteExecute` is deliberately absent. Do not add it on the
assumption that a Go binary never needs writable-executable pages — if you want
it, add it and prove it with Task 4's smoke test first.

- [ ] **Step 3: Write the maintainer scripts**

Create `packaging/preinst.sh`:

```sh
#!/bin/sh
set -e

# A fixed system user, not systemd's DynamicUser: a transient UID would leave
# /var/lib/kydns owned by a number that means nothing during an incident.
id -u kydns >/dev/null 2>&1 || \
	useradd --system --user-group --no-create-home \
		--shell /usr/sbin/nologin kydns
```

Create `packaging/postinst.sh`:

```sh
#!/bin/sh
set -e

systemctl daemon-reload >/dev/null 2>&1 || true
systemctl enable kydns.service >/dev/null 2>&1 || true

# Enabled but not started. KyDNS wants port 53, and starting it unasked on a
# host that already runs a resolver would take out that host's DNS.
cat <<'EOF'

KyDNS is installed but not running. Check that nothing else holds port 53:

  sudo ss -lnup 'sport = :53'

then start it:

  sudo systemctl start kydns

Read the one-time setup token and open the web UI:

  sudo cat /var/lib/kydns/setup-token
  ssh -L 8053:127.0.0.1:8053 <this-host>   # the UI is loopback-only
  http://127.0.0.1:8053/setup

EOF
```

Create `packaging/prerm.sh`:

```sh
#!/bin/sh
set -e

# $1 is "upgrade" on a dpkg upgrade and "1" on an rpm upgrade. Stopping and
# disabling then would leave the service down after an upgrade.
case "$1" in
remove | purge | 0)
	systemctl stop kydns.service >/dev/null 2>&1 || true
	systemctl disable kydns.service >/dev/null 2>&1 || true
	;;
esac
```

Create `packaging/postrm.sh`:

```sh
#!/bin/sh
set -e

systemctl daemon-reload >/dev/null 2>&1 || true

# Kept on purpose, including on purge. This directory is the entire registry
# and every credential KyDNS holds; removing a package must not be able to
# destroy it. The kydns user is kept too, because it still owns these files.
if [ -d /var/lib/kydns ]; then
	cat <<'EOF'

KyDNS data was left in /var/lib/kydns. It holds the registry database and
every credential, so removing the package does not remove it. Delete it
yourself once you are certain you no longer need it:

  sudo rm -rf /var/lib/kydns
  sudo userdel kydns

EOF
fi
```

Make them executable:

```bash
chmod +x packaging/*.sh
```

- [ ] **Step 4: Write the nfpm manifest**

Create `nfpm.yaml`:

```yaml
# Built per architecture by `make package`, which sets ARCH and VERSION.
name: kydns
arch: ${ARCH}
platform: linux
version: ${VERSION}
section: net
priority: optional
maintainer: Yoshi <yoshi@urlxl.com>
vendor: KyDNS
homepage: https://github.com/yoshiofthewire/kydns-server
license: AGPL-3.0-or-later
description: |
  Self-hosted local DNS server and service directory.
  KyDNS names private services on a home or homelab network, with per-subnet
  views, DHCP lease discovery, health checks, encrypted upstream forwarding,
  and opt-out blacklist filtering.

# DNS-over-TLS, DNS-over-HTTPS, and HTTPS health checks all need a trust store.
# The container gets one implicitly from its distroless base; a package has to
# ask for it.
depends:
  - ca-certificates

contents:
  - src: dist/kydns_linux_${ARCH}/kydns
    dst: /usr/bin/kydns
    file_info:
      mode: 0755

  - src: packaging/kydns.service
    dst: /lib/systemd/system/kydns.service
    file_info:
      mode: 0644

  # noreplace: an operator's edits survive an upgrade. 0644 is safe because
  # every field in this file is operational — listens, upstreams, TTLs, ACLs.
  # Credentials live in the database under /var/lib/kydns, which is 0700.
  - src: kydns.package.yaml
    dst: /etc/kydns/kydns.yaml
    type: config|noreplace
    file_info:
      mode: 0644

  - src: kydns.example.yaml
    dst: /usr/share/doc/kydns/kydns.example.yaml
    file_info:
      mode: 0644

# /var/lib/kydns is deliberately not listed. systemd's StateDirectory creates
# it with the right owner and mode, and dpkg never learns to remove it.

scripts:
  preinstall: packaging/preinst.sh
  postinstall: packaging/postinst.sh
  preremove: packaging/prerm.sh
  postremove: packaging/postrm.sh
```

- [ ] **Step 5: Add the build targets**

Replace the `.PHONY` line in `Makefile` and append the new targets:

```make
.PHONY: test build setup up dist package clean

# Debian versions must start with a digit, so a tag's leading "v" is stripped
# by the caller. This default is what a local build gets.
VERSION ?= 0.0.0-dev
ARCHES := amd64 arm64
DIST := dist

dist:
	rm -rf $(DIST)
	for arch in $(ARCHES); do \
		mkdir -p $(DIST)/kydns_linux_$$arch; \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$arch go build -trimpath \
			-ldflags "-s -w -X main.version=$(VERSION)" \
			-o $(DIST)/kydns_linux_$$arch/kydns ./cmd/kydns || exit 1; \
		cp kydns.example.yaml LICENSE $(DIST)/kydns_linux_$$arch/ || exit 1; \
		tar -czf $(DIST)/kydns_$(VERSION)_linux_$$arch.tar.gz \
			-C $(DIST)/kydns_linux_$$arch . || exit 1; \
	done

package: dist
	for arch in $(ARCHES); do \
		ARCH=$$arch VERSION=$(VERSION) \
			go tool nfpm package -f nfpm.yaml -p deb -t $(DIST) || exit 1; \
	done

clean:
	rm -rf $(DIST)
```

Add to `.gitignore`:

```
dist/
```

- [ ] **Step 6: Write the verification script**

Create `scripts/verify-package.sh`:

```sh
#!/bin/sh
# Static assertions on a built .deb: the manifest, the modes, the metadata.
# Runtime behaviour is checked separately by the CI smoke test.
#
# usage: scripts/verify-package.sh <deb-path> <expected-arch>
set -eu

deb=$1
arch=$2
fail=0

check() {
	if ! printf '%s\n' "$contents" | grep -qE "$1"; then
		echo "MISSING: $2"
		fail=1
	fi
}

contents=$(dpkg-deb -c "$deb")
info=$(dpkg-deb -I "$deb")

check '-rwxr-xr-x .* \./usr/bin/kydns$' '/usr/bin/kydns mode 0755'
check '-rw-r--r-- .* \./lib/systemd/system/kydns\.service$' 'the systemd unit, mode 0644'
check '-rw-r--r-- .* \./etc/kydns/kydns\.yaml$' '/etc/kydns/kydns.yaml mode 0644'
check '\./usr/share/doc/kydns/kydns\.example\.yaml$' 'the example config'

# /var/lib/kydns must NOT be in the package. systemd creates it, and dpkg must
# never learn it owns it — that is what keeps purge from deleting the database.
if printf '%s\n' "$contents" | grep -qE '\./var/lib/kydns'; then
	echo "PRESENT BUT MUST NOT BE: /var/lib/kydns is owned by the package"
	fail=1
fi

printf '%s\n' "$info" | grep -q 'Depends:.*ca-certificates' || {
	echo "MISSING: Depends on ca-certificates"
	fail=1
}

printf '%s\n' "$info" | grep -q "Architecture: $arch" || {
	echo "WRONG: architecture is not $arch"
	fail=1
}

dpkg-deb -I "$deb" conffiles 2>/dev/null | grep -q '/etc/kydns/kydns.yaml' || {
	echo "MISSING: /etc/kydns/kydns.yaml is not registered as a conffile"
	fail=1
}

if [ "$fail" -eq 0 ]; then
	echo "OK: $deb"
fi
exit "$fail"
```

Make it executable: `chmod +x scripts/verify-package.sh`

- [ ] **Step 7: Run the build and the verification**

Run:

```bash
make package VERSION=0.0.0-test
ls -la dist/
./scripts/verify-package.sh dist/kydns_0.0.0-test_amd64.deb amd64
./scripts/verify-package.sh dist/kydns_0.0.0-test_arm64.deb arm64
```

Expected: `OK: dist/...` twice, exit 0.

If a `check` fails on the mode pattern, run `dpkg-deb -c` by hand and adjust the
regex to the real output — do not relax the assertion to make it pass.

- [ ] **Step 8: Confirm the arm64 binary is really arm64**

Run: `file dist/kydns_linux_arm64/kydns`
Expected: output contains `ARM aarch64`. This catches a `GOARCH` that silently
did not apply.

- [ ] **Step 9: Commit**

```bash
git add packaging/ nfpm.yaml scripts/verify-package.sh Makefile .gitignore go.mod go.sum
git commit -m "feat: build a deb with a hardened systemd unit"
```

---

## Task 4: Prove the package on both architectures

Every safety property the unit claims gets tested. This runs on pull requests,
so packaging regressions surface before a tag is ever cut.

**Files:**
- Modify: `.github/workflows/ci.yml`
- Test: the job itself

**Interfaces:**
- Consumes: `make package` and `scripts/verify-package.sh` (Task 3).
- Produces: a `package` job whose name `release.yml` reuses conceptually but
  does not depend on.

- [ ] **Step 1: Add the package job**

Append to `.github/workflows/ci.yml`, as a new top-level job:

```yaml
  # Builds the deb and proves it on both architectures: it installs, it runs as
  # a non-root user, it binds a privileged port, its data survives a purge, and
  # an operator's config edits survive an upgrade.
  package:
    strategy:
      fail-fast: false
      matrix:
        include:
          - runner: ubuntu-latest
            arch: amd64
          - runner: ubuntu-24.04-arm
            arch: arm64
    runs-on: ${{ matrix.runner }}
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version-file: go.mod
          cache: true

      - name: build the package
        run: make package VERSION=0.0.0-ci

      - name: manifest is right
        run: ./scripts/verify-package.sh dist/kydns_0.0.0-ci_${{ matrix.arch }}.deb ${{ matrix.arch }}

      - name: installs
        run: |
          set -eux
          sudo apt-get update -qq
          sudo apt-get install -y -qq ./dist/kydns_0.0.0-ci_${{ matrix.arch }}.deb
          test -x /usr/bin/kydns
          /usr/bin/kydns version | grep -q '0.0.0-ci'

      # systemd-resolved holds 127.0.0.53:53 on GitHub runners, so binding
      # 0.0.0.0:53 would collide with it. 127.0.0.2:53 is free and still
      # privileged, which is the part that has to be proven.
      - name: configure for the runner
        run: |
          set -eux
          sudo tee /etc/kydns/kydns.yaml >/dev/null <<'YAML'
          data_dir: /var/lib/kydns
          dns:
            listen: "127.0.0.2:53"
            allow_query: ["127.0.0.0/8"]
          admin:
            listen: "127.0.0.1:8053"
          YAML

      - name: starts
        run: |
          set -eux
          sudo systemctl start kydns
          for i in $(seq 1 60); do
            curl -sf http://127.0.0.1:8053/api/v1/healthz && break
            sleep 1
          done
          systemctl is-active kydns

      - name: runs as a non-root user
        run: |
          set -eux
          pid=$(systemctl show -p MainPID --value kydns)
          uid=$(awk '/^Uid:/{print $2}' /proc/$pid/status)
          test "$uid" != "0" || { echo "kydns is running as root"; exit 1; }
          test "$(id -nu "$uid")" = "kydns"

      - name: state directory is locked down
        run: |
          set -eux
          test "$(sudo stat -c '%a %U' /var/lib/kydns)" = "700 kydns"
          test "$(sudo stat -c '%a' /var/lib/kydns/setup-token)" = "600"
          test "$(sudo stat -c '%a' /var/lib/kydns/bootstrap-token)" = "600"

      # The real proof that CAP_NET_BIND_SERVICE is sufficient: a name is
      # registered over the API and answered on a privileged port.
      - name: serves DNS on a privileged port
        run: |
          set -eux
          sudo apt-get install -y -qq dnsutils
          token=$(sudo cat /var/lib/kydns/bootstrap-token)
          curl -sf -X POST -H "Authorization: Bearer $token" \
            -H 'Content-Type: application/json' \
            -d '{"name":"ci","addresses":[{"address":"192.168.1.20"}]}' \
            http://127.0.0.1:8053/api/v1/services
          answer=$(dig @127.0.0.2 -p 53 ci.home.arpa A +short)
          test "$answer" = "192.168.1.20" || {
            echo "resolved '$answer', wanted 192.168.1.20"; exit 1; }

      - name: record the hardening score
        run: systemd-analyze security kydns.service || true

      - name: an operator's config edits survive an upgrade
        run: |
          set -eux
          echo "# operator edit, must survive" | sudo tee -a /etc/kydns/kydns.yaml
          make package VERSION=9.9.9-upgrade
          sudo apt-get install -y -qq ./dist/kydns_9.9.9-upgrade_${{ matrix.arch }}.deb
          grep -q "operator edit, must survive" /etc/kydns/kydns.yaml || {
            echo "the upgrade clobbered the operator's config"; exit 1; }
          grep -q "127.0.0.2:53" /etc/kydns/kydns.yaml

      - name: purge keeps the data
        run: |
          set -eux
          sudo apt-get purge -y -qq kydns
          test -d /var/lib/kydns || {
            echo "purge destroyed the registry"; exit 1; }
          test -f /var/lib/kydns/kydns.db || {
            echo "purge destroyed the database"; exit 1; }

      - name: logs on failure
        if: failure()
        run: sudo journalctl -u kydns --no-pager -n 200 || true
```

- [ ] **Step 2: Run the same sequence locally before pushing**

On an amd64 Linux host, run the `build the package`, `manifest is right`,
`installs`, `configure for the runner`, `starts`, `runs as a non-root user`,
and `state directory is locked down` steps by hand. Expected: all pass.

This is where a too-tight `SystemCallFilter` will surface — as a service that
fails to start with `SIGSYS` in `journalctl -u kydns`. If that happens, do not
delete the whole hardening block. Find the offending directive by removing them
one at a time, and leave a one-line comment in the unit naming what needed it.

- [ ] **Step 3: Clean up the local install**

```bash
sudo apt-get purge -y kydns
sudo rm -rf /var/lib/kydns
sudo userdel kydns
```

- [ ] **Step 4: Push and confirm the job is green on both architectures**

Run: `git push` and watch the `package (ubuntu-latest, amd64)` and
`package (ubuntu-24.04-arm, arm64)` jobs.
Expected: both green. The arm64 runner is free because this repository is
public.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "test: prove the deb installs, runs unprivileged, and keeps data"
```

---

## Task 5: The release workflow

**Files:**
- Create: `.github/workflows/release.yml`
- Test: a pre-release tag

**Interfaces:**
- Consumes: `make package` (Task 3).
- Produces: GitHub Release assets — `kydns_<v>_linux_<arch>.tar.gz`,
  `kydns_<v>_<arch>.deb`, and `SHA256SUMS`.

- [ ] **Step 1: Write the workflow**

Create `.github/workflows/release.yml`:

```yaml
name: Release

# Separate from ci.yml so the write permissions a release needs never apply to
# a pull request build.
on:
  push:
    tags: ["v*"]
  workflow_dispatch:

permissions:
  contents: read

jobs:
  release:
    runs-on: ubuntu-latest
    permissions:
      contents: write     # create the release
      id-token: write     # keyless attestation
      attestations: write
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version-file: go.mod
          cache: true

      # Debian versions must start with a digit, so the tag's leading v goes.
      # A manual run is not a release; it just proves the workflow still works.
      - name: resolve the version
        id: version
        run: |
          if [ "$GITHUB_REF_TYPE" = "tag" ]; then
            echo "version=${GITHUB_REF_NAME#v}" >> "$GITHUB_OUTPUT"
          else
            echo "version=0.0.0-dev+${GITHUB_SHA:0:7}" >> "$GITHUB_OUTPUT"
          fi

      - name: build binaries and packages
        run: make package VERSION=${{ steps.version.outputs.version }}

      - name: manifests are right
        run: |
          set -eux
          v=${{ steps.version.outputs.version }}
          ./scripts/verify-package.sh dist/kydns_${v}_amd64.deb amd64
          ./scripts/verify-package.sh dist/kydns_${v}_arm64.deb arm64

      - name: checksums
        run: |
          cd dist
          sha256sum *.tar.gz *.deb > SHA256SUMS
          cat SHA256SUMS

      # Keyless, free, and verifiable with `gh attestation verify`. Signing
      # from the first release is far cheaper than retrofitting it once people
      # are already downloading unsigned binaries.
      - uses: actions/attest-build-provenance@v2
        with:
          subject-path: "dist/*.tar.gz, dist/*.deb"

      - uses: actions/upload-artifact@v4
        with:
          name: kydns-${{ steps.version.outputs.version }}
          path: |
            dist/*.tar.gz
            dist/*.deb
            dist/SHA256SUMS

      - name: publish the release
        if: github.ref_type == 'tag'
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          gh release create "$GITHUB_REF_NAME" \
            --title "$GITHUB_REF_NAME" \
            --generate-notes \
            dist/*.tar.gz dist/*.deb dist/SHA256SUMS
```

- [ ] **Step 2: Commit and push**

```bash
git add .github/workflows/release.yml
git commit -m "ci: publish signed binaries and debs on a version tag"
git push
```

- [ ] **Step 3: Exercise it without cutting a release**

Run the workflow manually from the Actions tab (`workflow_dispatch`), or:

```bash
gh workflow run release.yml
gh run watch
```

Expected: green, with an artifact named `kydns-0.0.0-dev+<sha>` containing four
files plus `SHA256SUMS`, and no GitHub Release created.

- [ ] **Step 4: Cut a real pre-release tag**

```bash
git tag v0.0.1-rc1
git push origin v0.0.1-rc1
gh run watch
```

Expected: a `v0.0.1-rc1` release with `kydns_0.0.1-rc1_linux_amd64.tar.gz`,
`kydns_0.0.1-rc1_linux_arm64.tar.gz`, `kydns_0.0.1-rc1_amd64.deb`,
`kydns_0.0.1-rc1_arm64.deb`, and `SHA256SUMS`.

- [ ] **Step 5: Verify the attestation and the download**

```bash
gh release download v0.0.1-rc1 -p '*amd64.deb'
gh attestation verify kydns_0.0.1-rc1_amd64.deb --repo yoshiofthewire/kydns-server
```

Expected: verification succeeds and names this repository's workflow.

- [ ] **Step 6: Confirm the version really is stamped**

```bash
sudo apt-get install -y ./kydns_0.0.1-rc1_amd64.deb
kydns version
```

Expected: prints `0.0.1-rc1`. Then clean up as in Task 4 Step 3.

---

## Task 6: Document installing from the package

A package nobody knows how to install is not shipped.

**Files:**
- Modify: `README.md`
- Test: manual read-through

**Interfaces:**
- Consumes: everything above.
- Produces: nothing later tasks depend on.

- [ ] **Step 1: Add the install section**

Add to `README.md`, near the existing install/run material:

````markdown
## Install from a package

Debian and Ubuntu, including Raspberry Pi OS, on `amd64` and `arm64`:

```sh
# pick the .deb matching your architecture from the latest release
curl -LO https://github.com/yoshiofthewire/kydns-server/releases/latest/download/kydns_<version>_arm64.deb
sudo apt install ./kydns_<version>_arm64.deb
```

Verify it came from this repository's CI before installing:

```sh
gh attestation verify kydns_<version>_arm64.deb --repo yoshiofthewire/kydns-server
```

The package installs KyDNS but does not start it, because KyDNS wants port 53
and your host may already run a resolver. Check, then start:

```sh
sudo ss -lnup 'sport = :53'
sudo systemctl start kydns
```

Then read the one-time setup token and create your admin account:

```sh
sudo cat /var/lib/kydns/setup-token
```

The web UI listens on `127.0.0.1:8053` only. KyDNS speaks plain HTTP, so reach
it over an SSH tunnel:

```sh
ssh -L 8053:127.0.0.1:8053 <your-host>
```

then open `http://127.0.0.1:8053/setup`. To publish it on your LAN instead,
change `admin.listen` in `/etc/kydns/kydns.yaml` to `0.0.0.0:8053` — and put a
TLS-terminating reverse proxy in front of it.

| Path | What it is |
|---|---|
| `/etc/kydns/kydns.yaml` | Configuration. Your edits survive upgrades. |
| `/var/lib/kydns` | Database and tokens. **Back this up.** |
| `/usr/share/doc/kydns/kydns.example.yaml` | Every setting, documented. |

Removing the package leaves `/var/lib/kydns` in place, even with
`apt purge` — it holds your whole registry and every credential. Delete it
yourself when you are sure.
````

- [ ] **Step 2: Check the links and commands**

Confirm the release URL pattern matches what Task 5 Step 4 actually produced,
and that the `apt install ./file.deb` form is what Task 4 used.

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: explain installing KyDNS from a deb"
```

---

## Self-Review

**Spec coverage:**

| Spec section | Task |
|---|---|
| Version stamping | 1 |
| Release workflow, tag trigger, separate permissions | 5 |
| Artifacts: tarball, deb, SHA256SUMS | 3 (build), 5 (checksums, upload) |
| Provenance attestation | 5 |
| Package layout table, `Depends: ca-certificates`, license | 3 |
| Shipped config, `admin.listen` stays loopback | 2 |
| Maintainer scripts, `postrm` keeps data | 3 |
| `DynamicUser` rejected | 3 (comment in `preinst.sh`) |
| The unit and its hardening | 3 |
| `MemoryDenyWriteExecute` omitted until proven | 3 Step 2, 4 Step 2 |
| Verification tests 1-7 | 4 |
| Out of scope: image, armv6/7, rpm, apt repo | not implemented, by design |
| Notes for the image spec | not implemented — they are notes for a later spec |

**Type consistency:** `main.version` is defined in Task 1 and referenced by the
`-ldflags` in Tasks 1, 3, and 5, spelled identically. `make package VERSION=`
and `ARCH`/`VERSION` environment names match between the `Makefile` and
`nfpm.yaml`. `scripts/verify-package.sh <deb> <arch>` is called with two
arguments in Tasks 3, 4, and 5.

**Known risk, called out rather than hidden:** the `nfpm` `file_info.mode`
output format and the exact `dpkg-deb -c` column layout drive the regexes in
`verify-package.sh`. Task 3 Step 7 says to check the real output and tighten the
regex rather than relax the assertion — that is the step where this gets
settled, not a thing to discover in CI.
