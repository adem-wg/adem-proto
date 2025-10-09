cat ./*.jws | go run github.com/adem-wg/adem-proto/cmd/emblemcheck -trusted-pk ./auth.felixlinker.de.pub.pem -trusted-pk-alg ES512
