#!/bin/sh
# Create the LAN-attached Docker network that KyDNS joins.
#
# Idempotent, and never destructive: if the network already exists this
# reports what it is and stops. Other containers may be on it.
#
# Everything not set is derived from the host's default route. Override with
# KYDNS_NETWORK, KYDNS_NET_DRIVER, KYDNS_PARENT_IF, KYDNS_SUBNET, KYDNS_GATEWAY.
set -eu

# Environment first, then .env, then detection — the order docker compose uses.
from_env() { [ -f .env ] || return 0; sed -n "s/^$1=//p" .env | tail -1; }

NAME="${KYDNS_NETWORK:-$(from_env KYDNS_NETWORK)}"
IP="${KYDNS_IP:-$(from_env KYDNS_IP)}"
DRIVER="${KYDNS_NET_DRIVER:-$(from_env KYDNS_NET_DRIVER)}"
PARENT="${KYDNS_PARENT_IF:-$(from_env KYDNS_PARENT_IF)}"
SUBNET="${KYDNS_SUBNET:-$(from_env KYDNS_SUBNET)}"
GATEWAY="${KYDNS_GATEWAY:-$(from_env KYDNS_GATEWAY)}"
NAME="${NAME:-br0}"

DOCKER="docker"
docker network ls >/dev/null 2>&1 || DOCKER="sudo docker"

if $DOCKER network inspect "$NAME" >/dev/null 2>&1; then
	echo "Network '$NAME' already exists. Leaving it alone."
	$DOCKER network inspect "$NAME" --format \
'  driver:  {{.Driver}}
  parent:  {{index .Options "parent"}}
  subnet:  {{range .IPAM.Config}}{{.Subnet}}{{end}}
  range:   {{range .IPAM.Config}}{{.IPRange}}{{end}}'
	exit 0
fi

: "${PARENT:=$(ip -o -4 route show default | awk '{print $5; exit}')}"
[ -n "$PARENT" ] || { echo "No default route: set KYDNS_PARENT_IF in .env" >&2; exit 1; }
[ -e "/sys/class/net/$PARENT" ] || { echo "No such interface: $PARENT" >&2; exit 1; }

: "${GATEWAY:=$(ip -o -4 route show default | awk '{print $3; exit}')}"
: "${SUBNET:=$(ip -o -4 route show dev "$PARENT" proto kernel scope link | awk '{print $1; exit}')}"
[ -n "$SUBNET" ] || { echo "Could not read the subnet on $PARENT: set KYDNS_SUBNET in .env" >&2; exit 1; }

# An access point drops frames from the second MAC address macvlan needs, so
# wireless parents get ipvlan, which shares the host's MAC instead.
if [ -z "$DRIVER" ]; then
	if [ -d "/sys/class/net/$PARENT/wireless" ]; then
		DRIVER=ipvlan
		echo "$PARENT is wireless, using ipvlan. Some access points still drop this."
	else
		DRIVER=macvlan
	fi
fi

# Confine Docker's allocations to the one address KyDNS uses. Handing it the
# whole subnet invites it to pick something the router later leases to a
# phone, which presents as DNS failing at random hours of the day.
[ -n "$IP" ] || { echo "Set KYDNS_IP in .env first: it is the address KyDNS answers on" >&2; exit 1; }

echo "Creating network '$NAME':"
echo "  driver:  $DRIVER"
echo "  parent:  $PARENT"
echo "  subnet:  $SUBNET"
echo "  gateway: $GATEWAY"
echo "  range:   $IP/32"

$DOCKER network create -d "$DRIVER" \
	-o parent="$PARENT" \
	--subnet "$SUBNET" \
	--gateway "$GATEWAY" \
	--ip-range "$IP/32" \
	"$NAME"

echo "Done. 'docker compose up -d' will join it."
echo "Note: $DRIVER blocks traffic between the host and its own containers."
echo "See docker-compose.yml for the shim if this host resolves through KyDNS."
