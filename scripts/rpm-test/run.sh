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
# A docker tag can't hold the colon in "fedora:latest", so flatten it.
tag=kydns-rpm-test:$(echo "$base" | tr -c 'a-zA-Z0-9_.' '-')

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

docker build --build-arg "BASE=$base" -t "$tag" "$here"

# --privileged and the cgroup mount are what let systemd run as PID 1. This
# is a test host, not a deployment shape.
docker run -d --name "$name" --privileged --cgroupns=host \
	-v /sys/fs/cgroup:/sys/fs/cgroup:rw \
	-v "$rpm_pkg":/pkgs/base.rpm:ro \
	-v "$upgrade_pkg":/pkgs/upgrade.rpm:ro \
	"$tag" >/dev/null

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
