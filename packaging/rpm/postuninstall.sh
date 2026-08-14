#!/bin/sh
set -e

systemctl daemon-reload >/dev/null 2>&1 || true

# Kept on purpose. This directory is the entire registry and every credential
# KyDNS holds; removing a package must not be able to destroy it. The kydns
# user is kept too, because it still owns these files.
#
# The $1 test is what keeps an upgrade — postuninstall with 1 — from telling
# an operator their data was left behind by a removal that never happened.
if [ "$1" = "0" ] && [ -d /var/lib/kydns ]; then
	cat <<'EOF'

KyDNS data was left in /var/lib/kydns. It holds the registry database and
every credential, so removing the package does not remove it. Delete it
yourself once you are certain you no longer need it:

  sudo rm -rf /var/lib/kydns
  sudo userdel kydns

EOF
fi
