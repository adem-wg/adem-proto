os=$(uname -s)
arch=$(uname -m)
for cmd in "bundle" "ctcheck" "emblemcheck" "emblemgen" "kid" "leafhash" "nameserver" "probe" "records" "rootsetupcheck"; do
  go build -o "release/$cmd-$os-$arch" "github.com/adem-wg/adem-proto/cmd/$cmd"
done
