- This repository contains the code for the implementation of a digital emblem, ADEM. A digital emblem is the digital equivalent to the physical emblems of the Red Cross, Crescent, and Crystal, or more generally, emblems recognized under International Humanitarian Law (IHL).

# ADEM

In the following, I will briefly introduce ADEM and how it functions.
- ADEM specifies two types of so called *tokens*, emblems and endorsements, which are statements signed by a designated issuer.
- An emblem marks a digital asset as protected under IHL.
- Endorsements either (a) attest that an emblem was signed by a specific issuer (internal endorsements), or (b) endorse an issuer as legitimately issuing emblems (external endorsements).
  - Internal endorsements: Issuers can manage their keys in hierarchies, i.e., an emblem should be accompanied by one or more endorsements. The first endorsement endorses the emblem signing key, the next one that endorsements signing key, etc. The final endorsement will be signed by a root key.
  - External endorsements: An organization can use their root key to endorse another organization's root key.
  - Root keys: If they decide to use one, every organization must commit to their root key by submitting a specifically crafted Web PKI certificate to the Certificate Transparency (CT) infrastructure.
- Currently, we foresee to distribute ADEM tokens using the DNS, but this may be extended in the future.
- More details are provided in two specifications:
  - https://adem-wg.github.io/adem-core-spec/draft-linker-diem-adem-core.html
  - https://adem-wg.github.io/adem-dns-spec/draft-linker-diem-adem-dns.html
- It can happen that specification and implementation are out-of-sync. In general, assume that this is an error. Do not fix this error unless explicitly requested. If the error is non-blocking, only mention it in your summary. If the error is blocking, abort and ask how to proceed.
  - It can happen that you will be asked to implement a change not yet present in the specification, e.g., to test it before adjusting the specification accordingly. The prompt should make this explicit. In such cases, proceed to implement changes that are not described in the specification.

# Repository

- The programming language is Go.
- The repository provides CLI-focussed tools. They should work nicely together using stdin/stdout. The code for individual commands is provided in `cmd` and its subdirectories.
- Aim to reuse as much existing code as possible.
- Always check whether you can reuse existing code before implementing new features.
- When you find yourself reimplementing functionality or logic that has already been implemented, directly reuse or, when not immediately possible, generalize existing code.
- Re-run tests whenever possible. If you implement new features, also implement corresponding test cases. You can re-run all tests by executing `go test ./...` or test individual packages by running `go test github.com/adem-wg/adem-proto/pkg/...` (where the three dots are replaced by the package to test).
- Favor simple code. Simplify your logic whenever possible.
- The repository contains the following packages:
  - `pkg/args`: Defines common arguments among CLI tools.
  - `pkg/consts`: Provides string constants used in the spec.
  - `pkg/gen`: Generating tokens.
  - `pkg/ident`: Identifying assets and comparing identifiers.
  - `pkg/roots`: Verifying root key commitments and code related to that.
  - `pkg/tokens`: Parsing and handling tokens.
  - `pkg/util`: Utility code, e.g., for base64 parsing.
  - `pkg/vfy`: Verifying sets of tokens.
