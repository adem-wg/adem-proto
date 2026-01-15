/*
This tool probes for ADEM tokens and untrusted verification keys. It currently
supports probing DNS TXT records and writes the discovered material to stdout
as newline-separated tokens followed by a JWK set.
*/
package main

import (
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"regexp"

	"github.com/adem-wg/adem-proto/pkg/args"
	"github.com/adem-wg/adem-proto/pkg/tokens"
	"github.com/adem-wg/adem-proto/pkg/util"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

func init() {
	args.AddProbeArgs()
}

var (
	tokenValueGroup                = 2
	tokenReg        *regexp.Regexp = regexp.MustCompile(`^adem(-.+)?=(.+)`)
)

func main() {
	flag.Parse()

	if args.ProbeDNS() {
		if tokens, err := probeDNS(args.LoadProbeTarget()); err != nil {
			log.Fatalf("could not probe dns: %s", err)
		} else {
			printTokens(tokens)
		}
	} else {
		log.Fatal("no probe mechanisms enabled")
	}
}

func probeDNS(name string) ([]string, error) {
	records, err := net.LookupTXT(name)
	if err != nil {
		return nil, err
	}

	tokens := make([]string, 0)
	for _, record := range records {
		if match := tokenReg.FindStringSubmatch(record); match != nil {
			tokens = append(tokens, match[tokenValueGroup])
		}
	}

	log.Printf("probed %d token(s) via DNS", len(tokens))
	return tokens, nil
}

// Decodes a base64-encoded ASN.1 public key into a JWK.
func parseKey(raw []byte, algHint jwa.SignatureAlgorithm) (jwk.Key, error) {
	if decoded, err := util.B64Dec(raw); err != nil {
		return nil, err
	} else if parsed, err := x509.ParsePKIXPublicKey(decoded); err != nil {
		return nil, err
	} else if algHint == jwa.NoSignature() {
		return nil, errors.New("cannot use none as algorithm")
	} else if jwkKey, err := jwk.Import(parsed); err != nil {
		return nil, err
	} else if err := jwkKey.Set("alg", algHint); err != nil {
		return nil, err
	} else if _, err := tokens.SetKID(jwkKey, true); err != nil {
		return nil, err
	} else {
		return jwkKey, nil
	}
}

func printTokens(tokens []string) {
	for _, token := range tokens {
		if _, err := fmt.Println(token); err != nil {
			log.Fatalf("error printing token: %s", err)
		}
	}
}
