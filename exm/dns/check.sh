go run github.com/adem-wg/adem-proto/cmd/probe emblem.felixlinker.de > tokens
cat tokens | go run github.com/adem-wg/adem-proto/cmd/emblemcheck
