// emblemcheck verifies line-separated hexadecimal CWTs, including untrusted COSE public keys.
package main

import (
	"flag"
	"log"
	"os"

	"github.com/adem-wg/adem-proto/pkg/args"
	"github.com/adem-wg/adem-proto/pkg/tokens"
	"github.com/adem-wg/adem-proto/pkg/vfy"
)

func init() {
	args.AddCTArgs()
	args.AddVerificationArgs()
	args.AddVerificationLocalArgs()
}

func loadTokensLocal() ([][]byte, error) {
	file := args.LoadTokensFile()
	if file != nil {
		defer file.Close()
	}
	return tokens.ReadText(file)
}

func main() {
	offline := flag.Bool("offline", false, "disable CT network lookups; verify using local keys")
	flag.Parse()
	if !*offline {
		if err := args.FetchKnownLogs(); err != nil {
			log.Fatalf("could not fetch known logs: %s", err)
		}
	}
	ts, err := loadTokensLocal()
	if err != nil {
		log.Fatal(err)
	}

	trustedKeys := args.LoadTrustedKeys()
	if trustedKeys.Len() > 0 {
		if trustedKeys, err = tokens.SetAlgorithms(trustedKeys, args.LoadTrustedKeysAlg()); err != nil {
			log.Fatalf("could not set trusted keys KIDs: %s", err)
		}
	}

	result := vfy.VerifyTokensWithCT(ts, trustedKeys, !*offline)
	result.Print()
	if !result.Valid() {
		os.Exit(1)
	}
}
