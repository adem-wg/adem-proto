# Generate private key for signing if not exists
if [ ! -f private_emb.pem ]; then
  openssl ecparam -genkey -name secp521r1 -noout -out private_emb.pem
fi

go run github.com/adem-wg/adem-proto/cmd/emblemgen \
  -skey private_emb.pem -alg ES512 -proto emblem.json > emblem.jws
