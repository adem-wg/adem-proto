/*
This tool reads a CBOR array of COSE_Sign1 tokens and attempts to verify the
represented ADEM token set.
*/
package main

import (
	"flag"
	"log"

	"github.com/adem-wg/adem-proto/pkg/args"
	"github.com/adem-wg/adem-proto/pkg/vfy"
)

func init() {
	args.AddCTArgs()
	args.AddVerificationArgs()
	args.AddVerificationLocalArgs()
}

func main() {
	flag.Parse()
	if err := args.FetchKnownLogs(); err != nil {
		log.Fatalf("could not fetch known logs: %s", err)
	}

	messages := args.LoadTokens()
	rawTokens := make([][]byte, 0, len(messages))
	for _, message := range messages {
		raw, err := message.MarshalCBOR()
		if err != nil {
			log.Fatalf("could not encode token for verification: %s", err)
		}
		rawTokens = append(rawTokens, raw)
	}
	for _, key := range args.LoadVerificationKeys() {
		raw, err := key.MarshalCBOR()
		if err != nil {
			log.Fatalf("could not encode verification key: %s", err)
		}
		rawTokens = append(rawTokens, raw)
	}
	vfy.VerifyTokens(rawTokens, args.LoadTrustedKeys()).Print()
}
