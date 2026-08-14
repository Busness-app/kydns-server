#!/bin/sh
# Static assertions on a built package: the manifest, the modes, the metadata.
# Runtime behaviour is checked separately by the CI smoke tests.
#
# usage: scripts/verify-package.sh <package-path> <expected-arch>
#
# <expected-arch> is always the Go arch (amd64, arm64). The rpm backend maps
# it to the name rpm uses.
set -eu

pkg=$1
arch=$2
fail=0

note() {
	echo "$1"
	fail=1
}

# Both backends fill these, so the assertions below are format-agnostic:
#   contents  — one "mode /absolute/path" line per file
#   deps      — one dependency per line
#   pkgarch   — the architecture as the package records it
#   conffiles — one config-file path per line
#   scripts   — the maintainer scripts, one name per line
#   licpath   — where this format expects the licence text

case "$pkg" in
*.deb)
	command -v dpkg-deb >/dev/null 2>&1 || {
		echo "dpkg-deb is required to verify a .deb"; exit 2; }

	# dpkg-deb prints paths as ./usr/bin/kydns; strip the leading dot so the
	# rpm backend's absolute paths can share the same assertions.
	contents=$(dpkg-deb -c "$pkg" | awk '{ p=$NF; sub(/^\./, "", p); print $1, p }')
	info=$(dpkg-deb -I "$pkg")
	deps=$(printf '%s\n' "$info" | sed -n 's/^ *Depends: *//p' | tr ',' '\n' | sed 's/^ *//; s/ .*//')
	pkgarch=$(printf '%s\n' "$info" | sed -n 's/^ *Architecture: *//p')
	conffiles=$(dpkg-deb -I "$pkg" conffiles 2>/dev/null || true)
	scripts=$(for s in preinst postinst prerm postrm; do
		dpkg-deb -I "$pkg" "$s" >/dev/null 2>&1 && echo "$s" || true
	done)
	wantarch=$arch
	wantscripts="preinst postinst prerm postrm"
	licpath=/usr/share/doc/kydns/copyright

	# The deb must not have picked up the rpm's preset logic.
	if dpkg-deb -I "$pkg" postinst 2>/dev/null | grep -q 'systemctl preset'; then
		note "WRONG: the deb carries the rpm's preset scriptlet"
	fi
	;;
*.rpm)
	command -v rpm >/dev/null 2>&1 || {
		echo "rpm is required to verify a .rpm (apt-get install rpm)"; exit 2; }

	contents=$(rpm -qlvp "$pkg" | awk '{ print $1, $NF }')
	deps=$(rpm -qp --requires "$pkg" | sed 's/ .*//')
	pkgarch=$(rpm -qp --qf '%{ARCH}' "$pkg")
	conffiles=$(rpm -qp --configfiles "$pkg")
	scripts=$(rpm -qp --scripts "$pkg" | sed -n 's/^\([a-z]*\) scriptlet.*/\1/p')
	case "$arch" in
	amd64) wantarch=x86_64 ;;
	arm64) wantarch=aarch64 ;;
	*) echo "no rpm arch known for $arch"; exit 2 ;;
	esac
	wantscripts="preinstall postinstall preuninstall postuninstall"
	licpath=/usr/share/licenses/kydns/LICENSE

	# The licence has to carry rpm's %license flag, not just live at the
	# right path, or `rpm -qL` and the doc-stripping tools ignore it.
	rpm -qp --qf '[%{FILENAMES} %{FILEFLAGS:fflags}\n]' "$pkg" |
		grep -q "^$licpath l$" ||
		note "MISSING: $licpath is not marked as a licence"

	# The deb's postinst is gated on dpkg's "configure" argument, which rpm
	# never passes. If it is in here, every install is a silent no-op.
	if rpm -qp --scripts "$pkg" | grep -q '"configure"'; then
		note "WRONG: the rpm carries the deb's postinst; it would never run"
	fi
	;;
*)
	echo "unknown package format: $pkg"
	exit 2
	;;
esac

check() {
	printf '%s\n' "$contents" | grep -qE -- "$1" || note "MISSING: $2"
}

check '^-rwxr-xr-x /usr/bin/kydns$' '/usr/bin/kydns mode 0755'
check '^-rw-r--r-- /lib/systemd/system/kydns\.service$' 'the systemd unit, mode 0644'
check '^-rw-r--r-- /etc/kydns/kydns\.yaml$' '/etc/kydns/kydns.yaml mode 0644'
check '/usr/share/doc/kydns/kydns\.example\.yaml$' 'the example config'
check "^-rw-r--r-- $licpath\$" "the AGPL text at $licpath"

# /var/lib/kydns must NOT be in the package. systemd creates it, and the
# package manager must never learn it owns it — that is what keeps a removal
# from deleting the database.
if printf '%s\n' "$contents" | grep -q ' /var/lib/kydns'; then
	note "PRESENT BUT MUST NOT BE: /var/lib/kydns is owned by the package"
fi

printf '%s\n' "$deps" | grep -qx 'ca-certificates' ||
	note "MISSING: a dependency on ca-certificates"

test "$pkgarch" = "$wantarch" ||
	note "WRONG: architecture is $pkgarch, wanted $wantarch"

printf '%s\n' "$conffiles" | grep -qx '/etc/kydns/kydns.yaml' ||
	note "MISSING: /etc/kydns/kydns.yaml is not registered as a config file"

for want in $wantscripts; do
	printf '%s\n' "$scripts" | grep -qx "$want" ||
		note "MISSING: maintainer script $want"
done

if [ "$fail" -eq 0 ]; then
	echo "OK: $pkg"
fi
exit "$fail"
