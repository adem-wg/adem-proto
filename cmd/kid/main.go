/*
This tool converts a COSE key or PEM key to a public COSE key and computes its
COSE Key Thumbprint. With -key-out, it writes a CBOR array containing the key.
*/
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/adem-wg/adem-proto/pkg/args"
	"github.com/adem-wg/adem-proto/pkg/tokens"
	"github.com/fxamacker/cbor/v2"
)

var keyOut bool

func init() {
	args.AddPublicKeyArgs()
	flag.BoolVar(&keyOut, "key-out", false, "Set to output entire key. Otherwise output base32-encoded key identifier.")
}

func main() {
	flag.Parse()

	if publicKey := args.LoadPublicKey(); publicKey == nil {
		log.Fatal("no public key provided")
	} else {
		if keyOut {
			if key, err := publicKey.MarshalCBOR(); err != nil {
				log.Fatalf("could not encode COSE key: %s", err)
			} else if raw, err := cbor.Marshal([][]byte{key}); err != nil {
				log.Fatalf("could not encode COSE key array: %s", err)
			} else if _, err := os.Stdout.Write(raw); err != nil {
				log.Fatalf("could not write COSE key array: %s", err)
			}
		} else if kid, err := tokens.COSEThumbprintB32(publicKey); err != nil {
			log.Fatalf("could not hash key: %s", err)
		} else {
			fmt.Println(kid)
		}
	}
}
