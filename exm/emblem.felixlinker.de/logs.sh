for sub in "auth" "emblem"; do
  go run github.com/adem-wg/adem-proto/cmd/leafhash \
    -cert "certs/$sub.felixlinker.de.fullchain.pem" \
    > "certs/$sub.felixlinker.de.logs.json"
done
