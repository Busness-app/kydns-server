#!/bin/sh
set -e

# A fixed system user, not systemd's DynamicUser: a transient UID would leave
# /var/lib/kydns owned by a number that means nothing during an incident.
id -u kydns >/dev/null 2>&1 || \
	useradd --system --user-group --no-create-home \
		--shell /usr/sbin/nologin kydns
