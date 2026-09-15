#!/bin/sh
set -eu
cd "$(dirname "$0")"
# A queries exercise IHLE delivery in the Additional section.
go run ../../cmd/probe -server 127.0.0.1:8053 -qtype A example.test > tmp/probed.hex
go run ../../cmd/emblemcheck -offline -tokens tmp/probed.hex \
  -trusted-pk tmp/authority.pub.pem -trusted-pk-alg ES256
