# v0.5.0 pairing fixture

`pairing-v050.json` was generated using an isolated Go module requiring
`github.com/Busness-app/ky-primitives v0.5.0` and Go 1.26.6. The exact generator
is `pairing-v050-generator.go.txt`; copy it to `main.go` in a temporary module,
pin v0.5.0, run `go mod tidy`, confirm `go list -m` reports v0.5.0, then run it.

All values are synthetic. The deployment key is 32 bytes of 0x42, the token is
`synthetic-v050-token`, and the URL is `https://recovery.example`. The recovery
private key is discarded by the generator. Random public keys and encryption
nonces mean regeneration produces different bytes. Keep this frozen fixture
to prove future releases read an actual old sealed pairing without rewriting it.
