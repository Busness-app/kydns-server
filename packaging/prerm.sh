#!/bin/sh
set -e

# $1 is "upgrade" on a dpkg upgrade and "1" on an rpm upgrade. Stopping and
# disabling then would leave the service down after an upgrade.
case "$1" in
remove | purge | 0)
	systemctl stop kydns.service >/dev/null 2>&1 || true
	# Disabling through the helper also clears the state it recorded on
	# install, which is what lets postinst re-enable the unit if the package is
	# installed again. A bare `systemctl disable` leaves that state behind and
	# the reinstalled unit stays disabled.
	if command -v deb-systemd-helper >/dev/null 2>&1; then
		deb-systemd-helper disable kydns.service >/dev/null 2>&1 || true
	else
		systemctl disable kydns.service >/dev/null 2>&1 || true
	fi
	;;
esac
