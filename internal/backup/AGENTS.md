# Backup package

This package is the product-side KyRecovery boundary.

- Use `ky-primitives` for capsule and recovery-key formats. Compatibility belongs there.
- KyDNS holds only the recovery public key. Private recovery material may appear only in
  `Drill` with an ephemeral key and in the `restore` command from shares read on stdin.
- Snapshot SQLite through `store.SnapshotTo`; the WAL makes copying `kydns.db` unsafe.
- Keep the KyRecovery token encrypted under `data_dir/backup_key`. Status and errors never
  return either plaintext or ciphertext.
- Validate the recovery URL on parse and again on dial. Refuse redirects and non-public IPs.
- A receipt is durable only after its capsule ID, digest, and size match the deposited bytes.

Verification: `go test -race ./internal/backup ./internal/store`.
