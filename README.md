# ADEM Prototypes

This repository contains libraries and command line utilities that provide prototypes for *An Authentic Digital Emblem* (ADEM) as specified in the internet drafts:

- https://adem-wg.github.io/adem-core-spec/draft-linker-diem-adem-core.html
- https://adem-wg.github.io/adem-dns-spec/draft-linker-diem-adem-dns.html

## Prerequisites

All prototypes are written in the [Go programming language](https://go.dev/), version 1.24.0.
Clone this repository such that it is available on `$GOPATH`.

## Usage

Packages provided by this go module are located in `pkg` and can be imported as `github.com/adem-wg/adem-proto/pkg/...`.
Command line utilities can be executed by `go run github.com/adem-wg/adem-proto/cmd/...`.
The utilities are documented and examples are provided in `exm`.

## Acknowledgements

Work on this project was funded by the Werner Siemens-Stiftung (WSS).
We thank the WSS for their generous support.
