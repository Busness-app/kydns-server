#!/bin/sh
set -eu

# Prints "<url> <sha256>" for the newest Raspberry Pi OS Lite arm64 release
# that has been published for at least SOAK_DAYS. A release that has been up
# for three days has had three days for someone else to find the boot loop.
#
# Output goes straight into packaging/rpi-base.pin.

SOAK_DAYS=${SOAK_DAYS:-3}
index=https://downloads.raspberrypi.com/raspios_lite_arm64/images/

cutoff=$(date -u -d "-$SOAK_DAYS days" +%Y-%m-%d)

# The releases are dated directories, so the soak is a string comparison and
# the newest that passes it is the last one.
date=$(curl -fsS "$index" \
	| grep -o 'raspios_lite_arm64-[0-9]\{4\}-[0-9]\{2\}-[0-9]\{2\}' \
	| sed 's/.*-\([0-9-]\{10\}\)$/\1/' \
	| sort -u \
	| awk -v cutoff="$cutoff" '$0 <= cutoff' \
	| tail -1)
[ -n "$date" ] || { echo "no release older than $SOAK_DAYS days" >&2; exit 1; }

dir="${index}raspios_lite_arm64-$date/"
file=$(curl -fsS "$dir" \
	| grep -o '[0-9-]\{10\}-raspios-[a-z]*-arm64-lite\.img\.xz' \
	| sort -u | head -1)
[ -n "$file" ] || { echo "no lite image in $dir" >&2; exit 1; }

# Raspberry Pi publishes the checksum beside the image. Recording it here is
# what makes it a pin: the build refuses anything that stops matching what
# this repository reviewed.
sha=$(curl -fsS "$dir$file.sha256" | cut -d' ' -f1)
case $sha in
	[0-9a-f]*) [ "${#sha}" -eq 64 ] || { echo "bad checksum for $file: $sha" >&2; exit 1; } ;;
	*) echo "no checksum for $file" >&2; exit 1 ;;
esac

echo "$dir$file $sha"
