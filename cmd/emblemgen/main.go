package main

import (
	"flag"
	"log"

	"github.com/adem-wg/adem-proto/pkg/args"
	"github.com/adem-wg/adem-proto/pkg/gen"
)

func init() {
	args.AddSigningArgs()
	args.AddPublicKeyArgs()
}

func main() {
	flag.Parse()
	var signedToken []byte
	var err error
	endorseKey := args.LoadPublicKey()
	if endorseKey == nil {
		_, signedToken, err = gen.SignEmblem(
			args.LoadPrivateKey(),
			args.LoadAlg(),
			args.LoadClaimsProto(),
		)
	} else {
		_, signedToken, err = gen.SignEndorsement(
			args.LoadPrivateKey(),
			args.LoadAlg(),
			args.LoadClaimsProto(),
			endorseKey,
		)
	}

	if err != nil {
		log.Fatal(err)
	}
	log.Printf("%s\n", string(signedToken))
}
