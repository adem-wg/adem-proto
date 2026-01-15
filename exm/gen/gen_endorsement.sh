# Generate private key for signing if not exists
if [ ! -f private_end.pem ]; then
  openssl ecparam -genkey -name secp521r1 -noout -out private_end.pem
fi

go run github.com/adem-wg/adem-proto/cmd/emblemgen \
  -skey private_end.pem -alg ES512 -proto endorsement.json \
  -pk private_emb.pem > endorsement.jws
