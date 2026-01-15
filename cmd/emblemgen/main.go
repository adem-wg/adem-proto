/*
This tool generates and signs ADEM tokens (emblems and endorsements).
*/
package main

import (
	"flag"
	"fmt"
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
			args.LoadLifetime(),
			args.LoadSetVerifyJwk(),
		)
	} else {
		proto := args.LoadClaimsProto()
		logs := args.LoadLogs()
		if logs != nil {
			if err := proto.Set("log", logs); err != nil {
				log.Fatalf("could not set log in proto: %s", err)
			}
		}
		_, signedToken, err = gen.SignEndorsement(
			args.LoadPrivateKey(),
			args.LoadAlg(),
			args.LoadSetVerifyJwk(),
			proto,
			endorseKey,
			args.LoadPKAlg(),
			args.LoadLifetime(),
			args.LoadSignKid(),
		)
	}

	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(signedToken))
}
