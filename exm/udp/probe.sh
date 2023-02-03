go build github.com/adem-wg/adem-proto/cmd/probe
sudo ./probe -probe :6060 -trusted-pk endorsement.pem -trusted-pk-alg ES512
