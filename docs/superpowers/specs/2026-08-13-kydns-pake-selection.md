# Choosing a PAKE for peer pairing

Status: blocked — no candidate qualified
Date: 2026-08-13

## Why this decision exists

[Linked-server replication](2026-08-13-kydns-linked-server-replication-design.md)
pairs two nodes with a short code an operator reads off one screen and types
into another. That code is low-entropy by construction, and it cannot be sent
as a bearer token: before the two nodes have pinned each other's key
fingerprints there is nothing to authenticate a TLS certificate against, so a
machine-in-the-middle can present any certificate it likes and take the code as
it goes past. A balanced PAKE closes that hole, because it gives both sides
mutual authentication from the shared code without either side ever
transmitting it.

Neither the Go standard library nor `golang.org/x/crypto` provides one. This
was checked against the toolchain in use rather than assumed: `go list
golang.org/x/crypto/...` at v0.55.0 with Go 1.26.5 returns no package matching
`pake`, `cpace`, or `spake`. So the exchange needs a third-party library, and
that library carries the entire trust boundary of enrollment. It is the only
dependency this feature would add.

## What a candidate had to clear

A candidate had to be maintained, so that a defect found next year gets fixed.
It had to have outside cryptographic review, or provenance specific enough to
stand in for one — a port of a reviewed implementation, or a reference
implementation for a standard, not merely a competent-looking author. It had to
implement a specified protocol rather than an author's own construction, so
that the thing being trusted is the protocol the literature analysed. It had to
build with `CGO_ENABLED=0`, keep its transitive dependency list short, and
expose a two-message flow that can be driven over a byte-stream connection.

The bar is high on purpose. KyDNS promises never to compromise on security
without a documented reason. An unreviewed single-author cryptographic package
is worse than shipping this feature a quarter later.

## Candidates

| Package | Protocol | Licence | Last substantive change | Review | Dependencies |
|---|---|---|---|---|---|
| `filippo.io/cpace` | CPace, non-standard variant | BSD-3-Clause | Jan 2021, untagged | None | `gtank/ristretto255`, `x/crypto` |
| `github.com/bytemare/cpace` | CPace, draft-irtf-cfrg-cpace | MIT | Feb 2021, untagged | None | 7 modules, incl. a secp256k1 implementation |
| `github.com/schollz/pake/v3` | Boneh–Shoup PAKE2, textbook | MIT | Jul 2026, v3.2.0 | None | `edwards25519`, `tscholl2/siec` |
| `github.com/the-sarge/cpace` | CPace, draft-irtf-cfrg-cpace-21 | BSD-3-Clause | Aug 2026, v0.1.3 | None, stated | `edwards25519` |
| `salsa.debian.org/vasudev/gospake2` | SPAKE2 | GPL-3.0 / MIT | May 2021 | None, stated | small |
| `github.com/cloudflare/circl` | — | BSD-3-Clause | current | Partial, published | large |

`filippo.io/cpace` has the best author provenance of the set: Filippo Valsorda
maintains Go's cryptography and wrote much of the ristretto255 work it stands
on. The API is precisely the shape pairing wants — `Start`, `Finish`, two
messages, opaque bytes. The dependency tree is two modules and pure Go. It is
also, in its own package documentation, "an experimental implementation" that
"might change and be broken in unexpected ways", "really only a weekend
project", and "not standardized". It is loosely based on draft-haase-cpace-01
with HKDF substituted for parts of the key schedule, which is a deviation from
a draft that has itself since been superseded twenty times over. There is no
tagged release, and the last commit is from January 2021. Trusting it means
trusting an author's disclaimed prototype of a protocol variant nobody
analysed.

`github.com/bytemare/cpace` tracks the actual CFRG draft and its author has
worked on CFRG PAKE specifications, which is real provenance. The repository
has commits dated 2026, but they are continuous-integration maintenance; the
cryptographic code has not changed since February 2021. There is no tagged
release. The README says the implementation is proof of concept, and under the
heading "Deploy it" the entire body is "Don't, yet." Taking a dependency the
author tells you not to deploy is not a decision that can be defended. It also
pulls seven transitive modules, including a secp256k1 implementation this
project would never use.

`github.com/schollz/pake/v3` is the only candidate that is genuinely alive: a
v3.2.0 tag, commits within the last month, MIT, pure Go, two modules, and real
production exposure as the pairing layer of croc. Everything else about it
disqualifies it. The protocol is not a standard — it is the PAKE2 sketch from
page 789 of the Boneh–Shoup manuscript, implemented directly. The default group
is "siec", a curve introduced in a 2017 paper and implemented in Go by one
person. The README states plainly that the package does not implement the RFC
9382 key schedule or key-confirmation protocol and that applications must
perform mutual key confirmation themselves, which pushes the security-critical
half of the exchange back onto KyDNS. Public criticism of the construction
exists; a published cryptographic review does not. Maintenance alone does not
substitute for either a specification or a review.

`github.com/the-sarge/cpace` is the most recent arrival and implements the
current draft-21 with mandatory explicit key confirmation, which is the right
protocol and the right shape. Its own README settles the question: "This code
has not had independent cryptographic review and is not production-ready." The
repository is three months old, has one star, an anonymous author, and
development-journal and agent-instruction files indicating it was largely
machine-written. The honesty is creditable and the answer is still no.

`salsa.debian.org/vasudev/gospake2` implements SPAKE2 and interoperates with
the reference python-spake2, which is a form of provenance. Its documentation
states it has not been audited by a cryptographer and should not be considered
safe or correct. It has not been touched since 2021.

`github.com/cloudflare/circl` was checked because it is the one large Go
cryptography library with published review and active maintenance. It has no
PAKE. Its package list covers KEMs, signatures, OPRFs, threshold schemes and
zero-knowledge proofs, and stops there.

Two implementations were considered and set aside without full evaluation.
`psanford/wormhole-william` contains a well-exercised SPAKE2 compatible with
magic-wormhole, but it lives under `internal/` and is not importable; using it
would mean copying cryptographic code into this repository, which is
hand-rolling with extra steps. The remaining pkg.go.dev results for `spake2`
and `cpace` — `backkem/spake2-go`, `jtejido/spake2`, `jtejido/spake2plus`,
`niomon/spake2-go`, `lbodlev888/go-spake`, `CzarJoti/gospake2`,
`codahale/newplex`, `codahale/thyrse`, `bytemare/cake`, `armr-dev/cpace-go` —
are single-author proofs of concept, personal scheme playgrounds, or
demonstrations, none with a review or a stability claim.

## Decision

No candidate qualifies. Pairing is blocked pending a human decision.

The shape of the problem is consistent across every option. The
implementations with credible provenance are prototypes their own authors
disclaim and have not touched in five years. The implementation that is
actively maintained implements no standard, defaults to a novel curve, and
hands key confirmation back to the caller. Nothing in Go currently offers a
reviewed, maintained, specified balanced PAKE. CPace reached
draft-irtf-cfrg-cpace-21 without a Go implementation following it into
production, and that gap is the whole finding.

Substituting something else is not on the table, and the reason is worth
stating so it is not relitigated by accident. Sending the code as a bearer
token over TLS, sending a hash of it, or running an HMAC challenge-response
over the connection all fail identically: before the fingerprints are pinned
the certificate is unauthenticated, so an attacker in the path completes the
exchange with each side in turn and ends up pinned by both. That is exactly the
attack the PAKE exists to prevent, and no amount of hashing the code changes
it. Hand-rolling a PAKE is not on the table either.

## What unblocks this

Any one of the following, in rough order of preference.

A reviewed Go CPace implementation appearing, or `the-sarge/cpace` completing
the independent review its own documentation names as its release bar. That
would be re-evaluated against the criteria above and nothing else.

An operator-mediated fingerprint check replacing the PAKE: the primary displays
its key fingerprint, the replica displays the fingerprint it received, and the
operator confirms they match before pinning. This is the SSH model and it
defeats the machine-in-the-middle, because the attacker cannot make its own
fingerprint read the same as the primary's. It costs the operator a comparison
of a short string across two screens, which is friction this project generally
tries to remove. It is a genuine alternative rather than a weakening, and it
needs a human to weigh the friction against waiting.

Accepting the risk of an unreviewed dependency explicitly, with the
implementation named and the reasoning recorded here. That decision belongs to
the human, not to this document.

Until one of those happens, replication ships without pairing or does not ship.
The rest of the design — versioned snapshots, pinned transport, the pull loop,
read-only enforcement — is unaffected and stands on pinned fingerprints, which
pairing only needs to establish once.
