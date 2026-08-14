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
	expected=$(rpm -qp --qf "%{VERSION}" /pkgs/base.rpm | tr "~" "-")
	got=$(/usr/bin/kydns version)
	test "$got" = "$expected" || {
		echo "kydns version printed \"$got\", wanted \"$expected\""; exit 1; }
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

# The whole check is one shell invocation because it compares timestamps
# taken before and after the upgrade.
echo "== an operator's config edits survive an upgrade"
in_container '
	echo "# operator edit, must survive" >> /etc/kydns/kydns.yaml
	started_before=$(systemctl show -p ExecMainStartTimestamp --value kydns)

	expected=$(rpm -qp --qf "%{VERSION}" /pkgs/upgrade.rpm | tr "~" "-")
	upgrade_out=$(dnf -y upgrade /pkgs/upgrade.rpm)
	echo "$upgrade_out"

	# postuninstall guards its /var/lib/kydns notice on $1 = 0 so an upgrade
	# (postun with 1) stays quiet. Nothing else exercises that guard.
	if echo "$upgrade_out" | grep -q "KyDNS data was left in"; then
		echo "the upgrade printed the removal notice; the postun guard broke"
		exit 1
	fi

	# preset only runs on a first install ($1 = 1 in postinstall.sh). If a
	# future edit ran it on every upgrade too, the disable-by-default preset
	# on Fedora and Rocky would silently disable a unit the operator had
	# enabled -- the running process would be unaffected, so only this
	# assertion, not the ones above, would catch it before the next reboot.
	systemctl is-enabled kydns

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
	got=$(/usr/bin/kydns version)
	test "$got" = "$expected" || {
		echo "kydns version printed \"$got\" after upgrade, wanted \"$expected\""
		exit 1
	}
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

echo "OK: $rpm_pkg behaves on $base"
