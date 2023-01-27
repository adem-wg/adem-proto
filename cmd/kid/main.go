/*
This tool takes a public key as argument and calculates its KID using its
canonical JSON representation and SHA256. It prints the key in JWK JSON
serialization (see [RFC 7517]) to stdout.

[RFC 7517]: https://www.rfc-editor.org/rfc/rfc7517
*/
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"

	"github.com/adem-wg/adem-proto/pkg/args"
	"github.com/adem-wg/adem-proto/pkg/tokens"
)

func init() {
	args.AddPublicKeyArgs()
}

func main() {
	flag.Parse()

	key := args.LoadPublicKey()
	pkAlg := args.LoadPKAlg()

	if pk, err := key.PublicKey(); err != nil {
		log.Fatalf("could not get public key: %s", err)
	} else if err := pk.Set("alg", pkAlg.String()); err != nil {
		log.Fatalf("could not set alg: %s", err)
	} else if err := tokens.SetKID(pk); err != nil {
		log.Fatalf("could not hash key: %s", err)
	} else if bs, err := json.MarshalIndent(pk, "", "  "); err != nil {
		log.Fatalf("could not marshall JSON: %s", err)
	} else {
		fmt.Printf("%s\n", string(bs))
	}
}
