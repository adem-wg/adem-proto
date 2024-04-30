/*
This tool will read a number of newline seperated tokens in JWS compact
serialization (see [RFC 7515]) and attempt to verify them as ADEM tokens.

[RFC 7515]: https://www.rfc-editor.org/rfc/rfc7515
*/
package main

import (
	"bufio"
	"flag"
	"io"
	"log"

	"github.com/adem-wg/adem-proto/pkg/args"
	"github.com/adem-wg/adem-proto/pkg/tokens"
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

	file := args.LoadTokensFile()
	if file != nil {
		defer file.Close()
	}
	reader := bufio.NewReader(file)
	lines := [][]byte{}
	for {
		line, err := reader.ReadBytes('\n')
		if err == io.EOF {
			break
		} else if err != nil {
			log.Fatal(err)
		} else {
			lines = append(lines, line)
		}
	}

	trustedKeys := args.LoadTrustedKeys()
	if trustedKeys.Len() > 0 {
		var err error
		if trustedKeys, err = tokens.SetKIDs(trustedKeys, args.LoadTrustedKeysAlg()); err != nil {
			log.Fatalf("could not set trusted keys KIDs: %s", err)
		}
	}
	vfy.VerifyTokens(lines, trustedKeys).Print()
}
