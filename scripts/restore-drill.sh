#!/usr/bin/env bash
# Proves docs/RESTORE.md Step 1 against a capsule sealed to a fresh 2-of-3 key.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
# The helper has to live inside the module to import its dependencies.
# .superpowers/ is git-ignored; the trap removes it either way.
gen="$root/.superpowers/sdd/drill-gen-$$"
trap 'rm -rf "$work" "$gen"' EXIT
cd "$root"
go build -o "$work/kydns" ./cmd/kydns

# A throwaway key and a capsule sealed to it. The helper prints three share
# lines then writes the capsule; it exists only for this run.
mkdir -p "$gen"
cat > "$gen/main.go" <<'EOF'
package main

import (
	"fmt"
	"os"

	"github.com/Busness-app/ky-primitives/capsule"
	"github.com/Busness-app/ky-primitives/recoverykey"
)

func main() {
	priv, err := recoverykey.Generate()
	if err != nil {
		panic(err)
	}
	shares, err := recoverykey.Split(priv, 2, 3)
	if err != nil {
		panic(err)
	}
	for _, s := range shares {
		fmt.Fprintln(os.Stderr, s.String())
	}
	files := []capsule.File{
		{Path: "data/kydns.db", Content: []byte("not a real db; restore does not open it"), Mode: 0600},
		{Path: "data/backup_key", Content: make([]byte, 32), Mode: 0600},
		{Path: "config/kydns.yaml", Content: []byte("data_dir: /var/lib/kydns\n"), Mode: 0600},
	}
	raw, _, err := capsule.Seal("KyDNS", "drill", files, map[string]any{}, map[string]any{}, 2, 3, priv.Public())
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(os.Args[1], raw, 0600); err != nil {
		panic(err)
	}
	// A capsule sealed to a key these shares do not open.
	foreign, err := recoverykey.Generate()
	if err != nil {
		panic(err)
	}
	raw, _, err = capsule.Seal("KyDNS", "drill", files, map[string]any{}, map[string]any{}, 2, 3, foreign.Public())
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(os.Args[2], raw, 0600); err != nil {
		panic(err)
	}
}
EOF
go run "./.superpowers/sdd/drill-gen-$$" "$work/kydns.kycap" "$work/foreign.kycap" 2> "$work/shares.txt"
[ "$(wc -l < "$work/shares.txt")" -eq 3 ]

# Happy path: two shares on stdin.
mkdir -m 700 "$work/out"
head -2 "$work/shares.txt" | "$work/kydns" restore --capsule "$work/kydns.kycap" --out "$work/out"
test -f "$work/out/data/kydns.db" && test -f "$work/out/data/backup_key" && test -f "$work/out/config/kydns.yaml"
[ "$(stat -c %a "$work/out/data/backup_key")" = "600" ]

# One share: refused.
mkdir -m 700 "$work/one"
if head -1 "$work/shares.txt" | "$work/kydns" restore --capsule "$work/kydns.kycap" --out "$work/one"; then
	echo "one share was accepted" >&2; exit 1
fi

# A capsule sealed to another key: refused, and nothing is written.
mkdir -m 700 "$work/foreign"
if head -2 "$work/shares.txt" | "$work/kydns" restore --capsule "$work/foreign.kycap" --out "$work/foreign" 2> "$work/foreign.err"; then
	echo "a capsule sealed to another key was accepted" >&2; exit 1
fi
grep -q "capsule is sealed to a different recovery key" "$work/foreign.err"
[ -z "$(ls -A "$work/foreign")" ]

# Non-empty target: refused, and the existing file survives.
echo keep > "$work/out/marker"
if head -2 "$work/shares.txt" | "$work/kydns" restore --capsule "$work/kydns.kycap" --out "$work/out" 2> "$work/err.txt"; then
	echo "non-empty target was accepted" >&2; exit 1
fi
[ "$(cat "$work/out/marker")" = "keep" ]
# The refusal is the pre-check, not capsule.Open after the shares were typed.
grep -q "restore directory must be empty" "$work/err.txt"

# Shares never on argv: the command must not accept them there, even when the
# shares on stdin would otherwise open the capsule.
share=$(head -1 "$work/shares.txt")
mkdir -m 700 "$work/argv"
if head -2 "$work/shares.txt" | "$work/kydns" restore --capsule "$work/kydns.kycap" --out "$work/argv" "$share"; then
	echo "a share on argv was accepted" >&2; exit 1
fi
[ -z "$(ls -A "$work/argv")" ]
echo "restore drill: all checks passed"
