go run github.com/adem-wg/adem-proto/cmd/bundle ./*.cbor | \
  go run github.com/adem-wg/adem-proto/cmd/emblemcheck \
    -trusted-pk-pem ./private_end.pem
