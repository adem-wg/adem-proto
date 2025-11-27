go run github.com/adem-wg/adem-proto/cmd/emblemgen \
  -skey keys/emblem.pem -alg ES512 -proto protos/emblem.json \
  -lifetime 31536000  > jws/emblem.jws

go run github.com/adem-wg/adem-proto/cmd/emblemgen \
  -skey keys/emblem.felixlinker.de.pem -alg ES512 -proto protos/emblem.felixlinker.de.json \
  -pk keys/emblem.pem -sign-kid -lifetime 31536000 > jws/emblem.felixlinker.de.jws

go run github.com/adem-wg/adem-proto/cmd/emblemgen \
  -skey keys/auth.felixlinker.de.pem -alg ES512 -proto protos/auth.felixlinker.de.json \
  -pk keys/emblem.felixlinker.de.pem -sign-kid -lifetime 31536000 > jws/auth.felixlinker.de.jws

go run github.com/adem-wg/adem-proto/cmd/kid -cmd encode \
  -pk keys/auth.felixlinker.de.pem -pk-alg ES512 > jws/auth.felixlinker.de.pub

go run github.com/adem-wg/adem-proto/cmd/kid -cmd encode \
  -pk keys/emblem.felixlinker.de.pem -pk-alg ES512 > jws/emblem.felixlinker.de.pub

go run github.com/adem-wg/adem-proto/cmd/kid -cmd encode \
  -pk keys/emblem.pem -pk-alg ES512 > jws/emblem.pub
