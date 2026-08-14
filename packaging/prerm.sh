#!/bin/sh
set -e

# $1 is "upgrade" on a dpkg upgrade and "1" on an rpm upgrade. Stopping then
# would leave the service down after an upgrade; postinst restarts it instead.
case "$1" in
remove | purge | 0)
	# Stop only. Disabling here would delete the enable symlinks, and a
	# reinstall could not tell that apart from the operator disabling the
	# unit themselves, so it would come back disabled. postrm masks instead.
	systemctl stop kydns.service >/dev/null 2>&1 || true
	;;
esac
