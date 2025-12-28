/*
This tool probes for ADEM tokens and untrusted verification keys. It currently
supports probing DNS TXT records and writes the discovered material to stdout
as newline-separated tokens followed by a JWK set.
*/
package main

import (
	"crypto/x509"
	"encoding/json"
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
	tokenValueGroup                = 3
	tokenReg        *regexp.Regexp = regexp.MustCompile(`^adem-((emb|end)-\d+)=(.+)`)
	keyAlgGroup     int            = 1
	keyValueGroup   int            = 2
	keyReg          *regexp.Regexp = regexp.MustCompile(`^key-([A-Za-z0-9]+)=(.+)`)
)

func main() {
	flag.Parse()

	if args.ProbeDNS() {
		if tokens, keys, err := probeDNS(args.LoadProbeTarget()); err != nil {
			log.Fatalf("could not probe dns: %s", err)
		} else {
			printTokens(tokens)
			printKeys(keys)
		}
	} else {
		log.Fatal("no probe mechanisms enabled")
	}
}

func probeDNS(name string) ([]string, jwk.Set, error) {
	records, err := net.LookupTXT(name)
	if err != nil {
		return nil, nil, err
	}

	tokens := make([]string, 0)
	keys := jwk.NewSet()
	for _, record := range records {
		if match := tokenReg.FindStringSubmatch(record); match != nil {
			tokens = append(tokens, match[tokenValueGroup])
		} else if match := keyReg.FindStringSubmatch(record); match != nil {
			algStr := match[keyAlgGroup]
			rawKey := match[keyValueGroup]
			if alg, ok := jwa.LookupSignatureAlgorithm(algStr); !ok {
				log.Printf("unknown key algorithm in DNS TXT record: %s", algStr)
			} else if jwkKey, err := parseKey([]byte(rawKey), alg); err != nil {
				log.Printf("could not parse DNS key for alg %s: %s", algStr, err)
			} else {
				keys.AddKey(jwkKey)
			}
		}
	}

	log.Printf("probed %d token(s) and %d key(s) via DNS", len(tokens), keys.Len())
	return tokens, keys, nil
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

func printKeys(keys jwk.Set) {
	if keys != nil && keys.Len() > 0 {
		if raw, err := json.Marshal(keys); err != nil {
			log.Fatalf("error marshalling JWK set: %s", err)
		} else if _, err := fmt.Println(string(raw)); err != nil {
			log.Fatalf("error printing JWK set: %s", err)
		}
	}
}
