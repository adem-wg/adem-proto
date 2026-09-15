# ADEM Prototypes

This repository contains libraries and command line utilities that provide prototypes for *An Authentic Digital Emblem* (ADEM) as specified in the internet drafts:

- ../adem-core-spec/draft-linker-diem-adem-core.md
- ../adem-dns-spec/draft-linker-diem-adem-dns.md

## Prerequisites

### Binaries

Some binaries are available at the [releases page](https://github.com/adem-wg/adem-proto/releases).

### Compilation from Source

All prototypes are written in the [Go programming language](https://go.dev/), version 1.24.0.
To compile this project, you will naturally have to install that programming language.
After you have done so, clone this repository such that it is available on `$GOPATH`.

You can then compile a binary by running:

```sh
go build github.com/adem-wg/adem-proto/cmd/XXXXX
```

You can also run a command without producing a binary by running:

```sh
go run github.com/adem-wg/adem-proto/cmd/XXXXX
```

## Usage

We provide documentation in our [Wiki](https://github.com/adem-wg/adem-proto/wiki) and examples are in the [`exm`](/exm) directory.

In our documentation, we will reference individual commands by name only, e.g., `emblemcheck`.
We assume that you either compiled the respective binary (see above) or prefix the commands with `go run github.com/adem-wg/adem-proto/cmd/...`.

## Current local prototype

Start with [the local CWT/IHLE example](exm/local/README.md):

```sh
sh exm/local/prepare.sh
sh exm/local/serve.sh
# In a second terminal:
sh exm/local/check.sh
```

`emblemgen`, `records`, `probe`, and `emblemcheck` exchange one hexadecimal
CWT or bare public COSE_Key per line. Each IHLE wire record contains the original binary
CBOR bytes. Tokens use CWT tag 61 around COSE_Sign1 tag 18, protected `alg` and
`kid` headers, optional `typ = application/adem`, and integer registered claim
labels. Emblems and endorsements are distinguished by their required claims;
ambiguous combinations are rejected. The `iat` claim is optional. Both token kinds require a top-level numeric `prp`
bitmap (1–31); endorsements authorize the bits set in this bitmap. The former
`emb` map and its distribution, asset, and lifetime constraints are no longer
part of the token format. Asset identifier parsing and matching are unchanged. Key identifiers
are SHA-256 COSE Key Thumbprints, rendered as lowercase unpadded base32.
Keys use `cose.Key` throughout; on-wire keys are COSE_Key structures. Local key
files use PEM (SEC1/PKCS8 private keys, public keys, or certificates). JWK files
and the `-skey-jwk`, `-pk-jwk`, and `-trusted-pk-jwk` options are no longer
supported. The obsolete `-key-fmt` option has also been removed.
Claims use native `cose.CWTClaims` values, with direct CBOR encoding and explicit
ADEM validation. Editable JSON claim prototypes remain supported at the CLI
input boundary. No JWT structures or JSON conversions are used when processing
received CWTs. `kid` now emits a hexadecimal public COSE_Key by default;
`kid -kid-out` continues to emit the lowercase base32 key identifier.

The lightweight `nameserver` serves one owner over UDP and TCP on
`127.0.0.1:8053` by default. It includes the entire IHLE RRset in Additional for
other QTYPEs, sets TC without sending a partial RRset when UDP is too small,
and returns the complete set over TCP. `probe -server 127.0.0.1:8053 -qtype A
example.test` exercises this behavior. Both commands use experimental private-use
TYPE65400, configurable with `-ihle-type`, until IHLE receives an IANA assignment.

`emblemcheck -offline` disables CT queries. Supply locally trusted verification
keys through `-trusted-pk` and `-trusted-pk-alg`. Discovered COSE_Key records
provide verification material without establishing trust. As an intentional
extension to the core draft, results distinguish `SIGNED-TRUSTED`,
`ORGANIZATIONAL-TRUSTED`, and `ENDORSED-TRUSTED` from their `*-UNTRUSTED`
counterparts. The result contains the strongest trusted level and any strictly
stronger untrusted level, or `INVALID`. See `AGENTS.md` for the design decision.
Signature/time failures discard individual tokens; the remaining set must
contain exactly one emblem. An emblem without an issuer can validate without
endorsements. An emblem with an issuer requires an internal endorsement chain
with a verified root commitment.
Existing public JWT/TXT deployments and their old key commitments are historical
fixtures and are not expected to validate. Nothing is submitted to CT logs by
these examples.

CT log entries contain `id` and exactly one lookup field: `hash` for RFC 6962
logs or unsigned `index` for tiled/Static CT logs. The trusted log directory
must agree with the lookup method. The former `ver` field and combined
hash/index form are rejected. `leafhash` emits the current JSON shape.

Hex input is case-insensitive and permits whitespace within a record; command
pipes still separate records with newlines. Emitted record text uses uppercase.

The existing CT implementation checks inclusion and binding names, but does not
check certificate revocation; that remains a limitation relative to the core
specification. The examples do not establish production trust policy.

Run `go test ./...` for token, key, constraint, and local DNS integration tests.
The DNS integration tests require permission to bind loopback UDP/TCP ports.
