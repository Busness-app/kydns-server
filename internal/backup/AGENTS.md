# Backup package

## Purpose

`internal/backup` is KyDNS's adapter over `github.com/Busness-app/ky-primitives/recoveryclient`.
It owns only what differs per product: what a KyDNS capsule carries, the KyDNS drill
checks, and one `Service` that the admin routes, the scheduler and the CLI share. Pairing,
key pinning, sealing, delivery, retention, schedule and restore are the library's; a
behaviour that belongs to every product in the suite is fixed there, not here.

## Ownership

- `Collect` — the capsule's members and its verification recipe.
- `Drill` — the KyDNS checks (`required files`, `sqlite integrity`) run against the
  scratch directory the library extracts into. They only read: the database is verified
  with `store.VerifySnapshot`, never opened through `store.Open`, which creates the schema
  in an empty file and would report the hole it just filled as intact.
- `Service` — construction from `config.Config` and `store.Store`, the `Settings` and
  `Sealer` adapters, and `Status` for the admin screen.

## Local contracts

- `ServiceName` is both the name claimed at pairing and the name sealed into every
  manifest. KyRecovery refuses a deposit whose manifest names anything else.
- `backup_key` is created by `New` and is a required capsule member: it opens the sealed
  KyRecovery token, so a restore without it cannot resume deposits.
- `node_key` and `recovery.pub` are included when they exist and are then listed in
  `required_files`. A restored node needs `recovery.pub` beside its pin row or it cannot
  seal its next backup.
- The KyRecovery token is sealed with `NewAESGCMSealer(backup_key, "KyDNS:kyrecovery_token")`.
  Neither its plaintext nor its ciphertext appears in `Status` or in an error.
- The library reports a missing `recovery.pub` as `ErrNotPaired`. `Status` checks the
  `kyrecovery_key_id` row itself and reports `key_pin_missing` for a pin whose key file
  is gone: backups have stopped on an instance the operator believes is covered.
- Every caller records the run through `recoveryclient.Outcome`, so the same result
  writes the same audit event whichever entry point produced it.
- `SetSchedule` reads the stored value back, so the audit row and the API response say
  what the scheduler will actually use.
- No server code opens a suite-sealed capsule; only the `restore` command does, from
  custodian shares read on stdin.

## Verification

`go test -race ./internal/backup`. `nodecrypt_test.go` is the decrypt guard: it runs
`guardtest.NoDecryptOutside` over the whole repository and fails if anything but
`cmd/kydns/main.go`'s `run` reaches a share-combining or capsule-opening call.

## Child DOX Index

None.
