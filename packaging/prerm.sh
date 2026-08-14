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
