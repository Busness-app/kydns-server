#!/bin/sh
set -e

systemctl daemon-reload >/dev/null 2>&1 || true

if [ "$1" = "configure" ]; then
	# deb-systemd-helper records whether the operator deliberately disabled the
	# unit, so this both re-enables on a reinstall from the config-files state
	# and leaves a hand-disabled unit alone on an upgrade. init-system-helpers
	# is Priority: required on Debian and Ubuntu; the guard is for anywhere
	# else, where the $2 test is the best approximation we have.
	if command -v deb-systemd-helper >/dev/null 2>&1; then
		deb-systemd-helper enable kydns.service >/dev/null 2>&1 || true
	elif [ -z "$2" ]; then
		systemctl enable kydns.service >/dev/null 2>&1 || true
	fi

	# The new binary is on disk but the old one is still running, so an upgrade
	# would otherwise leave the security fix it carried unapplied. try-restart
	# is a no-op on a stopped unit, which keeps the first install below
	# installed-but-not-started.
	systemctl try-restart kydns.service >/dev/null 2>&1 || true

	# $2 is only set when dpkg is configuring over an existing version. The
	# banner is first-install only: an operator upgrading or reinstalling has
	# already minted a setup token and does not need these instructions again.
	if [ -z "$2" ]; then
		# Enabled but not started. KyDNS wants port 53, and starting it unasked
		# on a host that already runs a resolver would take out that host's DNS.
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
	fi
fi
