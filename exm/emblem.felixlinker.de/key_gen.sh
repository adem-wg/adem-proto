# Generate private keys for signing if they don't exist
if [ ! -d keys ]; then
  mkdir keys
fi

for f in "emblem" "emblem.felixlinker.de"; do
  if [ ! -f "keys/$f.pem" ]; then
    openssl ecparam -genkey -name secp521r1 -noout -out "keys/$f.pem"
  fi
  if [ ! -f "certs/$f.pub.pem" ]; then
    openssl ec -in "keys/$f.pem" -pubout > "certs/$f.pub.pem"
  fi
done
