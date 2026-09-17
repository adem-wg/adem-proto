/*
This tool reads a CBOR array of byte strings containing COSE_Sign1 tokens and
attempts to verify the represented ADEM token set.
*/
package main

import (
	"flag"
	"log"
	"slices"

	"github.com/adem-wg/adem-proto/pkg/args"
	"github.com/adem-wg/adem-proto/pkg/dns"
	"github.com/adem-wg/adem-proto/pkg/vfy"
)

var dnsName string

func init() {
	args.AddCTArgs()
	args.AddVerificationArgs()
	args.AddVerificationLocalArgs()
	flag.StringVar(&dnsName, "dns-name", "", "verify whether the emblem marks this name")
}

func main() {
	flag.Parse()
	if err := args.FetchKnownLogs(); err != nil {
		log.Fatalf("could not fetch known logs: %s", err)
	}

	rawTokens := args.LoadTokens()
	for _, key := range args.LoadVerificationKeys() {
		raw, err := key.MarshalCBOR()
		if err != nil {
			log.Fatalf("could not encode verification key: %s", err)
		}
		rawTokens = append(rawTokens, raw)
	}
	results := vfy.VerifyTokens(rawTokens, args.LoadTrustedKeys())
	if dnsName != "" && !slices.Contains(results.Results, vfy.INVALID) && !dns.MatchesAsset(dnsName, results.Marked) {
		log.Fatalf("verified emblem does not mark DNS name %s", dnsName)
	}
	results.Print()
}
