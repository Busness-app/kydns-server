#!/bin/sh
set -e

systemctl daemon-reload >/dev/null 2>&1 || true

# $2 is only set when dpkg is reconfiguring an existing install (an upgrade).
# Enabling and re-printing the banner then would silently re-enable a unit an
# operator deliberately disabled, and bind :53 again at the next boot.
if [ "$1" = "configure" ] && [ -z "$2" ]; then
	systemctl enable kydns.service >/dev/null 2>&1 || true

	# Enabled but not started. KyDNS wants port 53, and starting it unasked on
	# a host that already runs a resolver would take out that host's DNS.
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
