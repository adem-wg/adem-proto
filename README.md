# ADEM Prototypes

This repository contains libraries and command line utilities that provide prototypes for *An Authentic Digital Emblem* (ADEM) as specified in the internet drafts:

- https://www.ietf.org/archive/id/draft-linker-diem-adem-core-00.html
- https://www.ietf.org/archive/id/draft-linker-diem-adem-dns-00.html

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

We provide documentation in our [Wiki](/adem-wg/adem-proto/wiki) and examples are in the `exm` directory.

In our documentation, we will reference individual commands by name only, e.g., `emblemcheck`.
We assume that you either compiled the respective binary (see above) or prefix the commands with `go run github.com/adem-wg/adem-proto/cmd/...`.
