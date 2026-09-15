// kid computes a COSE Key Thumbprint and emits its text or a public COSE_Key.
package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/adem-wg/adem-proto/pkg/args"
	"github.com/adem-wg/adem-proto/pkg/tokens"
)

var kidOut bool

func init() {
	args.AddPublicKeyArgs()
	args.AddPublicKeyAlgArgs()
	flag.BoolVar(&kidOut, "kid-out", false, "Set to only output key ID. Otherwise output public key.")
}

func main() {
	flag.Parse()

	key := args.LoadPublicKey()
	pkAlg := args.LoadPKAlg()

	if pk, err := tokens.WithAlgorithm(key, pkAlg); err != nil {
		log.Fatalf("could not get public key: %s", err)
	} else if kid, err := tokens.CalcKID(pk); err != nil {
		log.Fatalf("could not hash key: %s", err)
	} else {
		if kidOut {
			fmt.Println(kid)
		} else if bs, err := tokens.EncodePublicCOSEKey(pk); err != nil {
			log.Fatalf("could not encode COSE key: %s", err)
		} else {
			fmt.Println(tokens.Text(bs))
		}
	}
}
