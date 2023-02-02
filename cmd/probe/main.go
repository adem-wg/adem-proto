/*
This tool sends an empty UDP packet to a given port and waits for emblems on
another specified port in response. Whenever it receives a set of tokens, it
verifies them.
*/
package main

import (
	"flag"
	"log"

	"github.com/adem-wg/adem-proto/pkg/args"
	"github.com/adem-wg/adem-proto/pkg/io"
	"github.com/adem-wg/adem-proto/pkg/tokens"
	"github.com/adem-wg/adem-proto/pkg/vfy"
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

	trustedKeys, err := tokens.SetKIDs(args.LoadTrustedKeys(), args.LoadTrustedKeysAlg())
	if err != nil {
		log.Fatalf("could not set trusted keys KIDs: %s", err)
	}

	results := make(chan io.TokenSet)
	go io.UDPProbe(args.ProbePort, args.LoadProbeAddr(), args.ProbeTimeout, results)
	for set := range results {
		if set == nil {
			break
		} else {
			vfy.VerifyTokens(set, trustedKeys).Print()
		}
	}
}
