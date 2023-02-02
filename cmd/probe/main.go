package main

import (
	"flag"
	"log"

	"github.com/adem-wg/adem-proto/pkg/args"
	"github.com/adem-wg/adem-proto/pkg/io"
	"github.com/adem-wg/adem-proto/pkg/roots"
	"github.com/adem-wg/adem-proto/pkg/vfy"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

func init() {
	args.AddProbeArgs()
	args.AddVerificationArgs()
}

func main() {
	flag.Parse()

	if !args.CTProviderApple && !args.CTProviderGoogle {
		log.Fatal("no log provider selected")
	}

	if args.CTProviderApple {
		if err := roots.FetchAppleKnownLogs(); err != nil {
			log.Fatalf("could not fetch Apple known logs: %s", err)
		}
	}

	if args.CTProviderGoogle {
		if err := roots.FetchGoogleKnownLogs(); err != nil {
			log.Fatalf("could not fetch Google known logs: %s", err)
		}
	}

	results := make(chan io.TokenSet)
	go io.UDPProbe(args.ProbePort, args.LoadProbeAddr(), args.ProbeTimeout, results)
	for set := range results {
		if set == nil {
			break
		} else {
			log.Print(vfy.VerifyTokens(set, jwk.NewSet()))
		}
	}
}
