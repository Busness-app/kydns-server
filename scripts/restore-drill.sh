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
 "path/filepath"

	"github.com/Busness-app/ky-primitives/recoveryclient"
 "github.com/Busness-app/kydns-server/internal/backup"
 "github.com/Busness-app/kydns-server/internal/config"
 "github.com/Busness-app/kydns-server/internal/store"
	"github.com/Busness-app/ky-primitives/recoverykey"
)

func main() {
 if os.Args[1] == "verify" {
  st, err := store.OpenSnapshot(filepath.Join(os.Args[2], "data/kydns.db"))
  if err != nil { panic(err) }
  defer st.Close()
  services, err := st.Services()
  if err != nil || len(services) != 1 || services[0].Name != "restore-sentinel" { panic("restored snapshot lost the sentinel service") }
  fmt.Println("restored KyDNS snapshot: integrity and sentinel verified")
  return
 }
 dir, err := os.MkdirTemp(filepath.Dir(os.Args[1]), "source-")
 if err != nil { panic(err) }
 st, err := store.Open(filepath.Join(dir, "kydns.db"))
 if err != nil { panic(err) }
 defer st.Close()
 if _, err := st.PutService(store.Service{Name: "restore-sentinel"}); err != nil { panic(err) }
 cfg := &config.Config{DataDir: dir, DNS: config.DNSConfig{Listen: ":53"}, Admin: config.AdminConfig{Listen: ":8053"}}
 service, err := backup.New(cfg, st, "drill")
 if err != nil { panic(err) }
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
 key := recoveryclient.RecoveryKey{Public: priv.Public(), Threshold: 2, TotalShares: 3}
 if err := recoveryclient.StoreRecoveryKey(dir, service.Settings(), key); err != nil { panic(err) }
 if err := recoveryclient.StorePairing(service.Settings(), service.Sealer(), "https://recovery.example", "synthetic-restore-token"); err != nil { panic(err) }
 payload, err := service.Collect()
 if err != nil { panic(err) }
 raw, _, err := recoveryclient.Seal(payload, key)
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(os.Args[1], raw, 0600); err != nil {
		panic(err)
	}
	// A capsule sealed to a key these shares do not open, and one share of
	// that other split for the mixed-shares case.
	foreign, err := recoverykey.Generate()
	if err != nil {
		panic(err)
	}
	otherShares, err := recoverykey.Split(foreign, 2, 3)
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(os.Args[3], []byte(otherShares[1].String()+"\n"), 0600); err != nil {
		panic(err)
	}
	raw, _, err = recoveryclient.Seal(payload, recoveryclient.RecoveryKey{Public: foreign.Public(), Threshold: 2, TotalShares: 3})
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(os.Args[2], raw, 0600); err != nil {
		panic(err)
	}
}
EOF
go run "./.superpowers/sdd/drill-gen-$$" "$work/kydns.kycap" "$work/foreign.kycap" "$work/other-share.txt" 2> "$work/shares.txt"
[ "$(wc -l < "$work/shares.txt")" -eq 3 ]

# Happy path: two shares on stdin.
mkdir -m 700 "$work/out"
head -2 "$work/shares.txt" | "$work/kydns" restore --capsule "$work/kydns.kycap" --out "$work/out"
test -f "$work/out/data/kydns.db" && test -f "$work/out/data/backup_key" && test -f "$work/out/config/kydns.yaml"
[ "$(stat -c %a "$work/out/data/backup_key")" = "600" ]
go run "./.superpowers/sdd/drill-gen-$$" verify "$work/out"

# One share: refused.
mkdir -m 700 "$work/one"
if head -1 "$work/shares.txt" | "$work/kydns" restore --capsule "$work/kydns.kycap" --out "$work/one"; then
	echo "one share was accepted" >&2; exit 1
fi

# Shares from two different splits: refused.
mkdir -m 700 "$work/mixed"
if { head -1 "$work/shares.txt"; cat "$work/other-share.txt"; } | "$work/kydns" restore --capsule "$work/kydns.kycap" --out "$work/mixed" 2> "$work/mixed.err"; then
	echo "shares from two splits were accepted" >&2; exit 1
fi
grep -q "shares belong to different splits" "$work/mixed.err"

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
