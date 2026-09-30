mkdir -p tokens

go run github.com/adem-wg/adem-proto/cmd/emblemgen \
  -skey-pem keys/emblem.pem -alg ES512 -proto protos/emblem.json \
  -lifetime 31536000 > tokens/emblem.cbor

go run github.com/adem-wg/adem-proto/cmd/emblemgen \
  -skey-pem keys/emblem.felixlinker.de.pem -alg ES512 -proto protos/emblem.felixlinker.de.json \
  -logs certs/emblem.felixlinker.de.logs.cbor -pk-pem keys/emblem.pem -lifetime 31536000 \
  > tokens/emblem.felixlinker.de.cbor

for key in emblem emblem.felixlinker.de; do
  go run github.com/adem-wg/adem-proto/cmd/kid \
    -pk-pem "keys/$key.pem" -key-out > "tokens/$key.key.cbor"
done
