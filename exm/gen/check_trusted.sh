cat ./*.jws | go run github.com/adem-wg/adem-proto/cmd/emblemcheck \
  -trusted-pk ./private_end.pem -trusted-pk-alg ES512
