if [ ! -f emblem.pem ]; then
  openssl ecparam -genkey -name secp521r1 -noout -out emblem.pem
fi
if [ ! -f endorsement.pem ]; then
  openssl ecparam -genkey -name secp521r1 -noout -out endorsement.pem
fi

go run github.com/adem-wg/adem-proto/cmd/emblemgen \
  -skey endorsement.pem -alg ES512 -proto endorsement.json \
  -pk emblem.pem -set-jwk > endorsement.jws
go run github.com/adem-wg/adem-proto/cmd/emblemserver \
  -skey emblem.pem -alg ES512 -port 6060 -end "*.jws" -proto emblem.json \
  -timeout 0
