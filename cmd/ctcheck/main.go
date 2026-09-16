/*
This tool reads CBOR from stdin, attempts to parse it as the "log" claim of
endorsements, and verifies that the given certificates are committed to the
respective logs.
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

func init() {
	args.AddCTArgs()
}

func main() {
	flag.Parse()

	if bs, err := io.ReadAll(os.Stdin); err != nil {
		log.Fatalf("could not read from stdin: %s", err)
	} else if err := args.FetchKnownLogs(); err != nil {
		log.Fatalf("could not fetch known CT logs: %s", err)
	} else {
		logs := []*tokens.LogConfig{}
		if err := cbor.Unmarshal(bs, &logs); err != nil {
			log.Fatalf("could not decode CBOR: %s", err)
		} else {
			results := roots.VerifyInclusionConfig(logs)
			for _, r := range results {
				var msg string
				if r.Ok {
					msg = "certificate included in log"
				} else {
					msg = "inclusion check failed for log"
				}
				log.Printf("%s:\n\turl:  %s\n\tname: %s", msg, r.LogURL, r.LogID)
			}
		}
	}
}
