#!/bin/sh
# Static assertions on a built .deb: the manifest, the modes, the metadata.
# Runtime behaviour is checked separately by the CI smoke test.
#
# usage: scripts/verify-package.sh <deb-path> <expected-arch>
set -eu

deb=$1
arch=$2
fail=0

check() {
	if ! printf '%s\n' "$contents" | grep -qE -- "$1"; then
		echo "MISSING: $2"
		fail=1
	fi
}

contents=$(dpkg-deb -c "$deb")
info=$(dpkg-deb -I "$deb")

check '-rwxr-xr-x .* \./usr/bin/kydns$' '/usr/bin/kydns mode 0755'
check '-rw-r--r-- .* \./lib/systemd/system/kydns\.service$' 'the systemd unit, mode 0644'
check '-rw-r--r-- .* \./etc/kydns/kydns\.yaml$' '/etc/kydns/kydns.yaml mode 0644'
check '\./usr/share/doc/kydns/kydns\.example\.yaml$' 'the example config'

# /var/lib/kydns must NOT be in the package. systemd creates it, and dpkg must
# never learn it owns it — that is what keeps purge from deleting the database.
if printf '%s\n' "$contents" | grep -qE '\./var/lib/kydns'; then
	echo "PRESENT BUT MUST NOT BE: /var/lib/kydns is owned by the package"
	fail=1
fi

printf '%s\n' "$info" | grep -q 'Depends:.*ca-certificates' || {
	echo "MISSING: Depends on ca-certificates"
	fail=1
}

printf '%s\n' "$info" | grep -q "Architecture: $arch" || {
	echo "WRONG: architecture is not $arch"
	fail=1
}

dpkg-deb -I "$deb" conffiles 2>/dev/null | grep -q '/etc/kydns/kydns\.yaml' || {
	echo "MISSING: /etc/kydns/kydns.yaml is not registered as a conffile"
	fail=1
}

for script in preinst postinst prerm postrm; do
	dpkg-deb -I "$deb" "$script" >/dev/null 2>&1 || {
		echo "MISSING: maintainer script $script"
		fail=1
	}
done

if [ "$fail" -eq 0 ]; then
	echo "OK: $deb"
fi
exit "$fail"
