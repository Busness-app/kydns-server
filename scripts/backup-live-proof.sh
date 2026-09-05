#!/usr/bin/env bash
# Proves the Disaster recovery screen and its API against a real server on a
# throwaway data dir: the no-key warning, pin by hand, one backup run to a local
# destination, the audit rows, and the schedule read-back including "off".
# Nothing here touches a real KyRecovery: pairing needs a live one, see the PR.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
# A directory of our own by default. An operator who names one keeps it: this script
# deletes the directory it works in, so it refuses to adopt anything already there.
work=${KYDNS_LIVE_DIR:-}
dns_addr=${KYDNS_LIVE_DNS:-127.0.0.1:15353}
admin_addr=${KYDNS_LIVE_ADMIN:-127.0.0.1:18053}
# The key generator has to live inside the module to import its dependencies.
gen="$root/.superpowers/sdd/live-gen-$$"
pid=""

if [ -z "$work" ]; then
	work=$(mktemp -d)
elif [ -e "$work" ] && [ -n "$(ls -A "$work" 2>/dev/null)" ]; then
	echo "live proof: $work exists and is not empty; this script deletes what it works in" >&2
	exit 1
fi

# Installed only once $work is ours to delete.
cleanup() {
	if [ -n "$pid" ]; then
		kill -TERM "$pid" 2>/dev/null || true
		wait "$pid" 2>/dev/null || true
	fi
	rm -rf "$work" "$gen"
}
trap cleanup EXIT

api() { # api METHOD PATH [BODY]
	local method=$1 path=$2 body=${3:-}
	if [ -n "$body" ]; then
		curl -sS -X "$method" -H "Authorization: Bearer $token" \
			-H 'Content-Type: application/json' -d "$body" "http://$admin_addr$path"
	else
		curl -sS -X "$method" -H "Authorization: Bearer $token" "http://$admin_addr$path"
	fi
}

fail() { echo "live proof: $*" >&2; exit 1; }

cd "$root"
mkdir -p "$work/backups"
mkdir -m 700 -p "$work/data"
printf 'data_dir: %s/data\ndns:\n  listen: "%s"\nadmin:\n  listen: "%s"\n' \
	"$work" "$dns_addr" "$admin_addr" > "$work/kydns.yaml"

echo "== build"
go build -o "$work/kydns" ./cmd/kydns

echo "== a throwaway 2-of-3 recovery key (public half only)"
mkdir -p "$gen"
cat > "$gen/main.go" <<'EOF'
package main

import (
	"encoding/base64"
	"fmt"

	"github.com/Busness-app/ky-primitives/recoverykey"
)

// Prints the base64 public half of a fresh recovery key. The private half and
// its shares are discarded with the process: nothing here needs to open a capsule.
func main() {
	priv, err := recoverykey.Generate()
	if err != nil {
		panic(err)
	}
	fmt.Println(base64.StdEncoding.EncodeToString(priv.Public().Bytes()))
}
EOF
pubkey=$(go run "./.superpowers/sdd/live-gen-$$")
[ -n "$pubkey" ] || fail "no public key generated"

echo "== serve on $admin_addr with KYDNS_BACKUP_DIR=$work/backups"
KYDNS_BACKUP_DIR="$work/backups" "$work/kydns" serve --config "$work/kydns.yaml" \
	> "$work/serve.log" 2>&1 &
pid=$!
for _ in $(seq 1 200); do
	[ -s "$work/data/setup-token" ] && [ -s "$work/data/bootstrap-token" ] &&
		curl -sS -o /dev/null "http://$admin_addr/setup" && break
	kill -0 "$pid" 2>/dev/null || fail "server exited: $(cat "$work/serve.log")"
	sleep 0.2
done
grep -q 'setup token' "$work/serve.log" || fail "no setup token in the log"

setup_token=$(tr -d '\n' < "$work/data/setup-token")
token=$(tr -d '\n' < "$work/data/bootstrap-token")
[ -n "$setup_token" ] && [ -n "$token" ] || fail "empty setup or bootstrap token"

echo "== complete setup"
code=$(curl -sS -o /dev/null -w '%{http_code}' -c "$work/cookies" -X POST \
	"http://$admin_addr/setup" \
	--data-urlencode "token=$setup_token" \
	--data-urlencode 'password=a-long-throwaway-password' \
	--data-urlencode 'confirm=a-long-throwaway-password')
[ "$code" = "303" ] || fail "POST /setup = $code"

# Consume the complete HTML in grep checks: grep -q can close the pipe early
# and make curl fail under pipefail even when the expected text was found.
settings() { curl -sS -b "$work/cookies" "http://$admin_addr/settings"; }

echo "== before pinning: no recovery key"
status=$(api GET /api/v1/backup/status)
echo "$status"
echo "$status" | grep -q '"key_pinned":false' || fail "key_pinned should be false"
echo "$status" | grep -q '"paired":false' || fail "paired should be false"
echo "$status" | grep -q '"has_destination":true' || fail "the local dir is a destination"
settings | grep 'No recovery key' > /dev/null || fail "the screen should warn about the missing key"

echo "== pin the key by hand"
api POST /api/v1/backup/pin-key \
	"$(printf '{"public_key":"%s","threshold":2,"total_shares":3}' "$pubkey")" | tee "$work/pin.json"
grep -q '"threshold":2' "$work/pin.json" || fail "pin did not report 2-of-3"
key_id=$(sed -n 's/.*"recovery_key_id":"\([^"]*\)".*/\1/p' "$work/pin.json")
[ -n "$key_id" ] || fail "no recovery_key_id"

echo "== a second, different key is refused (write-once)"
other=$(go run "./.superpowers/sdd/live-gen-$$")
code=$(curl -sS -o "$work/pin2.json" -w '%{http_code}' -X POST \
	-H "Authorization: Bearer $token" -H 'Content-Type: application/json' \
	-d "$(printf '{"public_key":"%s","threshold":2,"total_shares":3}' "$other")" \
	"http://$admin_addr/api/v1/backup/pin-key")
cat "$work/pin2.json"; echo
[ "$code" = "409" ] || fail "a second key was not refused with 409 (got $code)"
# docs/RESTORE.md quotes this sentence to the operator, so the proof pins it.
grep -q 'already pinned to a different recovery key' "$work/pin2.json" ||
	fail "the 409 body is not the sentence the runbook quotes"

echo "== back up now"
# The response carries the whole manifest, encapsulated key and all. It goes to the
# file; stdout gets the one field a reader needs.
api POST /api/v1/backup/deposit > "$work/run.json"
capsule_id=$(sed -n 's/.*"capsule_id":"\([^"]*\)".*/\1/p' "$work/run.json")
[ -n "$capsule_id" ] || fail "no capsule id from the run"
echo "deposited $capsule_id"

echo "== the local copy"
ls -la "$work/backups"
copies=$(find "$work/backups" -maxdepth 1 -name 'KyDNS.*.kycap' | wc -l)
[ "$copies" -eq 1 ] || fail "expected one local copy, found $copies"
copy=$(find "$work/backups" -maxdepth 1 -name 'KyDNS.*.kycap')
[ "$(stat -c %a "$copy")" = "600" ] || fail "the local copy is not mode 600"

echo "== audit rows"
sqlite3 "$work/data/kydns.db" "SELECT action, outcome FROM audit_events ORDER BY id" | tee "$work/audit.txt"
grep -qx 'backup.key_pinned|success' "$work/audit.txt" || fail "no backup.key_pinned success row"
grep -qx 'admin.backup_run|success' "$work/audit.txt" || fail "no admin.backup_run success row"
grep -qx 'backup.key_pinned|failure' "$work/audit.txt" || fail "the refused pin was not audited"
# The library writes admin.backup_run details as a JSON object, not a sentence.
sqlite3 "$work/data/kydns.db" \
	"SELECT details FROM audit_events WHERE action='admin.backup_run' ORDER BY id LIMIT 1" \
	| grep -q '^{' || fail "admin.backup_run details is not a JSON object"

echo "== schedule: 900 seconds, then off"
api PUT /api/v1/backup/schedule '{"interval_sec":900}' | tee "$work/sched.json"
grep -q '"interval_sec":900' "$work/sched.json" || fail "schedule did not read back as 900"
api GET /api/v1/backup/status | grep -q '"interval_sec":900' || fail "status does not show 900"
settings | grep 'every 15 minutes' > /dev/null || fail "the screen does not show every 15 minutes"

api PUT /api/v1/backup/schedule '{"interval_sec":0}' | tee "$work/sched0.json"
grep -q '"interval_sec":0' "$work/sched0.json" || fail "schedule did not read back as off"
api GET /api/v1/backup/status | grep -q '"interval_sec":0' || fail "status does not show off"
settings | grep 'Schedule is off' > /dev/null || fail "the screen does not warn that the schedule is off"

echo "== SIGTERM"
kill -TERM "$pid"
for _ in $(seq 1 100); do
	kill -0 "$pid" 2>/dev/null || break
	sleep 0.1
done
if kill -0 "$pid" 2>/dev/null; then fail "the server did not exit on SIGTERM"; fi
wait "$pid" 2>/dev/null || true
pid=""

echo "backup live proof: all checks passed"
