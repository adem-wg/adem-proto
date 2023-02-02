package main

import (
	"flag"
	"log"

	"github.com/adem-wg/adem-proto/pkg/args"
	"github.com/adem-wg/adem-proto/pkg/io"
	"github.com/adem-wg/adem-proto/pkg/vfy"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

func init() {
	args.AddProbeArgs()
	args.AddVerificationArgs()
}

func main() {
	flag.Parse()

	if err := args.FetchKnownLogs(); err != nil {
		log.Fatalf("could not fetch known logs: %s", err)
	}


	results := make(chan io.TokenSet)
	go io.UDPProbe(args.ProbePort, args.LoadProbeAddr(), args.ProbeTimeout, results)
	for set := range results {
		if set == nil {
			break
		} else {
			vfy.VerifyTokens(set, jwk.NewSet()).Print()
		}
	}
}
