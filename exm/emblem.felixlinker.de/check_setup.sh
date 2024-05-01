for sub in "auth" "emblem"; do
  echo "Checking $sub.felixlinker.de"
  cat "certs/$sub.felixlinker.de.logs.json" | go run github.com/adem-wg/adem-proto/cmd/rootsetupcheck \
    -oi https://$sub.felixlinker.de -pk "certs/$sub.felixlinker.de.pub.pem" -pk-alg ES512
done
