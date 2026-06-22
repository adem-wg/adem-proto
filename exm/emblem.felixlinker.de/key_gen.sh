# Generate private keys for signing if they don't exist
if [ ! -d keys ]; then
  mkdir keys
fi

for f in "emblem" "auth.felixlinker.de" "emblem.felixlinker.de"; do
  if [ ! -f "keys/$f.pem" ]; then
    openssl ecparam -genkey -name secp521r1 -noout -out "keys/$f.pem"
  fi
  if [ ! -f "certs/$f.pub.pem" ]; then
    openssl ec -in "keys/$f.pem" -pubout > "certs/$f.pub.pem"
  fi
  if [ ! -f "certs/$f.pub.json" ]; then
    go run github.com/adem-wg/adem-proto/cmd/kid -pk "keys/$f.pem" -pk-alg ES512 > "certs/$f.pub.json"
  fi
done
