go run github.com/adem-wg/adem-proto/cmd/emblemgen \
  -skey keys/emblem.pem -alg ES512 -proto protos/emblem.json \
  -lifetime 31536000  > jws/emblem.jws

go run github.com/adem-wg/adem-proto/cmd/emblemgen \
  -skey keys/emblem.felixlinker.de.pem -alg ES512 -proto protos/emblem.felixlinker.de.json \
  -logs certs/emblem.felixlinker.de.logs.json -pk keys/emblem.pem -lifetime 31536000 \
  > jws/emblem.felixlinker.de.jws

go run github.com/adem-wg/adem-proto/cmd/emblemgen \
  -skey keys/auth.felixlinker.de.pem -alg ES512 -proto protos/auth.felixlinker.de.json \
  -logs certs/auth.felixlinker.de.logs.json -pk keys/emblem.felixlinker.de.pem -lifetime 31536000 \
  > jws/auth.felixlinker.de.jws
