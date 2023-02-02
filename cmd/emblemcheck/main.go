/*
This tool will read a number of newline seperated tokens in JWS compact
serialization (see [RFC 7515]) and attempt to verify them as ADEM tokens.

[RFC 7515]: https://www.rfc-editor.org/rfc/rfc7515
*/
package main

import (
	"bufio"
	"context"
	"flag"
	"io"
	"log"

	"github.com/adem-wg/adem-proto/pkg/args"
	"github.com/adem-wg/adem-proto/pkg/tokens"
	"github.com/adem-wg/adem-proto/pkg/vfy"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

func init() {
	args.AddVerificationArgs()
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

	trustedKeysIn := args.LoadTrustedKeys()
	trustedKeys := jwk.NewSet()
	ctx := context.TODO()
	iter := trustedKeysIn.Keys(ctx)
	for iter.Next(ctx) {
		k := iter.Pair().Value.(jwk.Key)
		if pk, err := k.PublicKey(); err != nil {
			log.Fatalf("could not get public key: %s", err)
		} else {
			if pk.Algorithm().String() == "" {
				if err := pk.Set("alg", args.LoadTrustedKeysAlg()); err != nil {
					log.Fatalf("could not set key alg: %s", err)
				}
			}
			if err := tokens.SetKID(pk, true); err != nil {
				log.Fatalf("could not set KID: %s", err)
			}
			trustedKeys.AddKey(pk)
		}
	}

	vfy.VerifyTokens(lines, trustedKeys).Print()
}
