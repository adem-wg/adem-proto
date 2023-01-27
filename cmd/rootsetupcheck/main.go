package main

import (
	"encoding/json"
	"flag"
	"io"
	"log"
	"os"

	"github.com/adem-wg/adem-proto/pkg/args"
	"github.com/adem-wg/adem-proto/pkg/roots"
	"github.com/adem-wg/adem-proto/pkg/tokens"
)

func init() {
	args.AddPublicKeyArgs()
	args.AddVerificationArgs()
}

func main() {
	flag.Parse()

	if pk := args.LoadPublicKey(); pk == nil {
		log.Fatal("no public key to verify")
	} else if iss := args.OI; iss == "" {
		log.Fatal("no issuer given")
	} else if bs, err := io.ReadAll(os.Stdin); err != nil {
		log.Fatalf("could not read from stdin: %s", err)
	} else if !args.CTProviderGoogle && !args.CTProviderApple {
		log.Fatalf("no trusted CT log providers selected")
	} else if err := roots.FetchGoogleKnownLogs(); err != nil {
		log.Fatalf("could not fetch Google known CT logs: %s", err)
	} else if err := roots.FetchAppleKnownLogs(); err != nil {
		log.Fatalf("could not fetch Apple known CT logs: %s", err)
	} else {
		logs := []*tokens.LogConfig{}
		if err := json.Unmarshal(bs, &logs); err != nil {
			log.Fatalf("could not decode json: %s", err)
		} else {
			results := roots.VerifyBindingCerts(iss, pk, logs)
			for _, r := range results {
				if r.Result {
					log.Printf("root key correctly committed to log:\n\t%s", r.LogID)
				} else {
					log.Printf("could not verify log: %s", r.LogID)
				}
			}
		}
	}
}
