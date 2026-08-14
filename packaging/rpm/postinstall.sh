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
