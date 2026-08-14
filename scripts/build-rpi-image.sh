#!/bin/sh
set -eu

usage() {
	echo "usage: $0 <arm64-deb> <output.img> [raspios-lite-url]" >&2
}

[ "$#" -ge 2 ] && [ "$#" -le 3 ] || { usage; exit 2; }

deb=$1
output=$2
base_url=${3:-https://downloads.raspberrypi.com/raspios_lite_arm64_latest}

[ "$(id -u)" -eq 0 ] || { echo "run as root (the image must be mounted)" >&2; exit 1; }
[ -f "$deb" ] || { echo "package not found: $deb" >&2; exit 1; }

command -v curl >/dev/null || { echo "curl is required" >&2; exit 1; }
command -v losetup >/dev/null || { echo "losetup is required" >&2; exit 1; }
command -v partx >/dev/null || { echo "partx is required" >&2; exit 1; }
command -v mount >/dev/null || { echo "mount is required" >&2; exit 1; }
command -v mountpoint >/dev/null || { echo "mountpoint is required" >&2; exit 1; }
command -v xz >/dev/null || { echo "xz is required" >&2; exit 1; }

work=$(mktemp -d)
loop=
root=$work/root
mkdir -p "$root"

cleanup() {
	set +e
	mountpoint -q "$root" && umount "$root"
	[ -z "$loop" ] || losetup -d "$loop"
	rm -rf "$work"
}
trap cleanup EXIT INT TERM

curl -fL "$base_url" -o "$work/base.download"

mkdir -p "$(dirname "$output")"
# The download decides whether it is compressed, not the URL: the published
# "latest" link names no file at all and still serves an .xz.
if xz --list "$work/base.download" >/dev/null 2>&1; then
	xz -dc "$work/base.download" > "$output"
else
	cp "$work/base.download" "$output"
fi

loop=$(losetup --find --show --partscan "$output")
udevadm settle 2>/dev/null || true
# --partscan already creates the nodes on most kernels, and adding partitions
# that are there is an error, so partx runs only where it is needed.
if [ ! -b "${loop}p2" ]; then
	partx --add "$loop"
	udevadm settle 2>/dev/null || true
fi

mount "${loop}p2" "$root"
install -d -m 0755 "$root/opt/kydns" "$root/usr/local/sbin" \
	"$root/etc/systemd/system/multi-user.target.wants"
install -m 0644 "$deb" "$root/opt/kydns/kydns.deb"
install -m 0644 packaging/kydns-image-install.service \
	"$root/etc/systemd/system/kydns-image-install.service"
install -m 0755 packaging/kydns-image-install \
	"$root/usr/local/sbin/kydns-image-install"
ln -s ../kydns-image-install.service \
	"$root/etc/systemd/system/multi-user.target.wants/kydns-image-install.service"

sync
# The mount needed root, the image does not. Left owned by root it is a file
# the caller cannot compress, copy, or delete without sudo of their own.
[ -z "${SUDO_UID:-}" ] || chown "$SUDO_UID:${SUDO_GID:-$SUDO_UID}" "$output"
echo "wrote $output"
