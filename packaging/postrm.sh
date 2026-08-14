#!/bin/sh
set -e

systemctl daemon-reload >/dev/null 2>&1 || true

# init-system-helpers is Priority: required on Debian and Ubuntu; the guard is
# for anywhere else.
if command -v deb-systemd-helper >/dev/null 2>&1; then
	case "$1" in
	remove)
		# Mask, never disable. Disabling deletes the enable symlinks but
		# leaves behind the state file that records them, and the helper
		# then reads "some links were recorded, none exist" as the operator
		# having disabled the unit — so the reinstall never recreates them.
		# Masking leaves the symlinks alone; postinst unmasks.
		deb-systemd-helper mask kydns.service >/dev/null 2>&1 || true
		;;
	purge)
		deb-systemd-helper purge kydns.service >/dev/null 2>&1 || true
		deb-systemd-helper unmask kydns.service >/dev/null 2>&1 || true
		;;
	esac
fi

# Kept on purpose, including on purge. This directory is the entire registry
# and every credential KyDNS holds; removing a package must not be able to
# destroy it. The kydns user is kept too, because it still owns these files.
if [ -d /var/lib/kydns ]; then
	cat <<'EOF'

KyDNS data was left in /var/lib/kydns. It holds the registry database and
every credential, so removing the package does not remove it. Delete it
yourself once you are certain you no longer need it:

  sudo rm -rf /var/lib/kydns
  sudo userdel kydns

EOF
fi
