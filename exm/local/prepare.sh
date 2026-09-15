#!/bin/sh
set -eu
cd "$(dirname "$0")"
mkdir -p tmp
for key in emblem authority; do
  if [ ! -f "tmp/$key.pem" ]; then
    openssl ecparam -genkey -name prime256v1 -noout -out "tmp/$key.pem"
  fi
  openssl ec -in "tmp/$key.pem" -pubout -out "tmp/$key.pub.pem" 2>/dev/null
done
go run ../../cmd/emblemgen -skey tmp/emblem.pem -alg ES256 -proto emblem.json > tmp/emblem.cwt
go run ../../cmd/emblemgen -skey tmp/authority.pem -alg ES256 -pk tmp/emblem.pub.pem -proto endorsement.json > tmp/endorsement.cwt
go run ../../cmd/records -pk-alg ES256 \
  tmp/emblem.cwt tmp/endorsement.cwt tmp/emblem.pub.pem tmp/authority.pub.pem > tmp/records.hex
