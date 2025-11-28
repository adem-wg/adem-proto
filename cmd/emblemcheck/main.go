/*
This tool will read a number of newline seperated tokens in JWS compact
serialization (see [RFC 7515]) and attempt to verify them as ADEM tokens.

[RFC 7515]: https://www.rfc-editor.org/rfc/rfc7515
*/
package main

import (
	"bufio"
	"crypto/x509"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/adem-wg/adem-proto/pkg/args"
	"github.com/adem-wg/adem-proto/pkg/tokens"
	"github.com/adem-wg/adem-proto/pkg/util"
	"github.com/adem-wg/adem-proto/pkg/vfy"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

func init() {
	args.AddCTArgs()
	args.AddVerificationArgs()
	args.AddVerificationLocalArgs()
}

var tokenIdGroup int = 1
var partGroup int = 4
var tokenGroup = 5
var tokenReg *regexp.Regexp = regexp.MustCompile(`^adem-((emb|end)-\d+)(-p(\d+))?=(.+)`)
var keyAlgGroup = 1
var keyValueGroup = 2
var keyReg *regexp.Regexp = regexp.MustCompile(`^key-([A-Za-z0-9]+)=(.+)`)

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

func loadTokensDNS() ([][]byte, jwk.Set, error) {
	if records, err := net.LookupTXT(args.AssetDomainName); err != nil {
		return nil, nil, err
	} else {
		tokens := map[string][]string{}
		keys := jwk.NewSet()
		for _, record := range records {
			if match := tokenReg.FindStringSubmatch(record); match != nil {
				tokenId := match[tokenIdGroup]
				if tokens[tokenId] == nil {
					tokens[tokenId] = []string{}
				}

				part := match[partGroup]
				if part == "" {
					tokens[tokenId] = append(tokens[tokenId], match[tokenGroup])
				} else if partInt, err := strconv.Atoi(part); err != nil {
					return nil, nil, err
				} else {
					tokens[tokenId] = util.Insert(tokens[tokenId], partInt, match[tokenGroup])
				}
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

		log.Print("Fetched the following tokens from the DNS...")
		bytesTokens := make([][]byte, 0, len(tokens))
		for k, v := range tokens {
			token := strings.Join(v, "")
			log.Printf("%s:\n%s", k, token)
			bytesTokens = append(bytesTokens, []byte(token))
		}
		if keys.Len() > 0 {
			log.Printf("Fetched %d key(s) from the DNS.", keys.Len())
		}
		return bytesTokens, keys, nil
	}
}

func loadTokensLocal() ([][]byte, error) {
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
			return nil, err
		} else {
			lines = append(lines, line)
		}
	}
	return lines, nil
}

func main() {
	flag.Parse()
	if err := args.FetchKnownLogs(); err != nil {
		log.Fatalf("could not fetch known logs: %s", err)
	}

	var ts [][]byte
	var keys jwk.Set
	var err error
	if args.AssetDomainName != "" {
		ts, keys, err = loadTokensDNS()
	} else {
		ts, err = loadTokensLocal()
		keys = args.LoadTokenKeySet()
	}

	if err != nil {
		log.Fatal(err)
	}

	trustedKeys := args.LoadTrustedKeys()
	if trustedKeys.Len() > 0 {
		if trustedKeys, err = tokens.SetKIDs(trustedKeys, args.LoadTrustedKeysAlg()); err != nil {
			log.Fatalf("could not set trusted keys KIDs: %s", err)
		}
	}

	vfy.VerifyTokens(ts, trustedKeys, keys).Print()
}
