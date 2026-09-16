/*
This tool generates and signs ADEM tokens (emblems and endorsements).
*/
package main

import (
	"flag"
	"log"
	"os"

	"github.com/adem-wg/adem-proto/pkg/args"
	"github.com/adem-wg/adem-proto/pkg/gen"
	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

func init() {
	args.AddSigningArgs()
	args.AddPublicKeyArgs()
}

func main() {
	flag.Parse()
	claims := args.LoadClaimsProto()
	endorseKey := args.LoadPublicKey()
	var message *cose.Sign1Message
	var err error
	if endorseKey == nil {
		message, err = gen.SignEmblem(args.LoadPrivateKey(), claims, args.LoadLifetime())
	} else {
		if logs := args.LoadLogs(); logs != nil {
			claims.Log = logs
		}
		message, err = gen.SignEndorsement(
			args.LoadPrivateKey(),
			claims,
			endorseKey,
			args.LoadLifetime(),
		)
	}

	if err != nil {
		log.Fatal(err)
	} else if signedTokens, err := cbor.Marshal([]*cose.Sign1Message{message}); err != nil {
		log.Fatalf("could not encode signed token array: %s", err)
	} else if _, err := os.Stdout.Write(signedTokens); err != nil {
		log.Fatalf("could not write signed token array: %s", err)
	}
}
