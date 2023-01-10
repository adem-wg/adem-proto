package main

import (
	"flag"
	"log"

	"github.com/adem-wg/adem-proto/pkg/args"
	"github.com/adem-wg/adem-proto/pkg/gen"
)

func main() {
	flag.Parse()
	emblem, err := gen.GenToken(
		args.LoadPrivateKey(),
		args.LoadAlg(),
		args.LoadClaimsProto(),
	)
	if err != nil {
		log.Fatal(err)
	}
	log.Println(emblem)
}