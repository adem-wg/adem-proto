# ADEM Prototypes

This repository contains libraries and command line utilities that provide prototypes for *An Authentic Digital Emblem* (ADEM) as specified in https://adem-wg.github.io/adem-spec/.
The prototypes are not fully specification compliant yet and will continue to evolve.

## Prerequisites

All prototypes are written in the [Go programming language](https://go.dev/).
To use them, you need to install go version 1.19 or higher.
After you have done so, you can clone this repository such that it is available on `$GOPATH`.

## Usage

Packages provided by this go module are located in `pkg` and can be imported as `github.com/adem-wg/adem-proto/pkg/...`.
Command line utilities can be executed by `go run github.com/adem-wg/adem-proto/cmd/...`.
The utilities are documented and examples are provided in `exm`.

## Acknowledgements

Work on this project was funded by the Werner Siemens-Stiftung (WSS).
We thank the WSS for their generous support.
