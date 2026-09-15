#!/bin/sh
set -eu
go run ../../cmd/records -trusted-pk-alg ES512 \
  emblem.cwt endorsement.cwt private_emb.pem private_end.pem > records.hex
go run ../../cmd/emblemcheck -offline -tokens records.hex \
  -trusted-pk private_end.pem -trusted-pk-alg ES512
