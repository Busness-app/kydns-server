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
