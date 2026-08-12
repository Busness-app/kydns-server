#!/bin/sh
# Fill in the network settings compose needs, by reading the host's default
# route. Getting these wrong by hand is the mistake this exists to prevent:
# an interface with no carrier looks fine in a config file and fails at
# `docker compose up` with an error that names neither the interface nor the
# reason.
#
# Only ever adds missing keys. An existing value is never changed, so this is
# safe to re-run.
set -eu

[ -f .env ] || { cp .env.example .env; echo "Created .env from .env.example"; }

have() { grep -q "^$1=." .env; }

add() {
	if have "$1"; then
		echo "  $1 already set, leaving it"
	elif [ -n "$2" ]; then
		printf '%s=%s\n' "$1" "$2" >> .env
		echo "  $1=$2"
	else
		echo "  $1 could not be detected — set it by hand" >&2
	fi
}

PARENT=$(ip -o -4 route show default | awk '{print $5; exit}')
GATEWAY=$(ip -o -4 route show default | awk '{print $3; exit}')
SUBNET=""
[ -n "$PARENT" ] && SUBNET=$(ip -o -4 route show dev "$PARENT" proto kernel scope link | awk '{print $1; exit}')

echo "Detected from the default route:"
add KYDNS_PARENT_IF "$PARENT"
add KYDNS_SUBNET "$SUBNET"
add KYDNS_GATEWAY "$GATEWAY"

if ! have KYDNS_IP; then
	echo
	echo "Set KYDNS_IP in .env before starting. It is the address KyDNS answers" >&2
	echo "on: inside $SUBNET, outside your router's DHCP pool, and not one another" >&2
	echo "DNS server already holds." >&2
	exit 1
fi

echo
echo "Ready. 'docker compose up -d' will create the network and start KyDNS."
