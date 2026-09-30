cat "certs/emblem.felixlinker.de.logs.cbor" | go run github.com/adem-wg/adem-proto/cmd/rootsetupcheck \
  -oi https://emblem.felixlinker.de -pk-pem "certs/emblem.felixlinker.de.pub.pem"
