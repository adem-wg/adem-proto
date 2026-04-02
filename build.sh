os=$(uname -s)
arch=$(uname -m)
for cmd in "ctcheck" "emblemcheck" "emblemgen" "kid" "leafhash" "probe" "records" "rootsetupcheck"; do
  go build -o "release/$cmd-$os-$arch" "github.com/adem-wg/adem-proto/cmd/$cmd"
done
