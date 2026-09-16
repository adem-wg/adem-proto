/*
This tool reads CBOR from stdin, attempts to parse it as the "log" claim of
endorsements, and verifies that the given public key is correctly committed to
the given OI in the logs.
*/
package main

import (
	"flag"
	"io"
	"log"
	"os"

	"github.com/adem-wg/adem-proto/pkg/args"
	"github.com/adem-wg/adem-proto/pkg/roots"
	"github.com/adem-wg/adem-proto/pkg/tokens"
	"github.com/fxamacker/cbor/v2"
)

var OI string

func init() {
	args.AddPublicKeyArgs()
	args.AddCTArgs()
	flag.StringVar(&OI, "oi", "", "OI to check root key log inclusion")
}

func main() {
	flag.Parse()

	if pk := args.LoadPublicKey(); pk == nil {
		log.Fatal("no public key to verify")
	} else if OI == "" {
		log.Fatal("no issuer given")
	} else if bs, err := io.ReadAll(os.Stdin); err != nil {
		log.Fatalf("could not read from stdin: %s", err)
	} else if err := args.FetchKnownLogs(); err != nil {
		log.Fatalf("could not fetch known CT logs: %s", err)
	} else {
		logs := []*tokens.LogConfig{}
		if err := cbor.Unmarshal(bs, &logs); err != nil {
			log.Fatalf("could not decode CBOR: %s", err)
		} else {
			results := roots.VerifyBindingCerts(OI, pk, logs)
			for _, r := range results {
				var msg string
				if r.Ok {
					msg = "root key correctly committed to log"
				} else {
					msg = "root key commitment verification failed for log"
				}
				log.Printf("%s:\n\turl:  %s\n\tname: %s", msg, r.LogURL, r.LogID)
			}
		}
	}
}
