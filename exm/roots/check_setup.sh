cat logs.json | go run github.com/adem-wg/adem-proto/cmd/rootsetupcheck \
  -oi https://auth.felixlinker.de -pk auth.felixlinker.de_pub.pem -pk-alg ES512
