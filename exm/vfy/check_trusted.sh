#!/bin/sh
set -eu
cd "$(dirname "$0")/../local"
exec go run ../../cmd/emblemcheck -offline -tokens tmp/records.hex \
  -trusted-pk tmp/authority.pub.pem -trusted-pk-alg ES256
