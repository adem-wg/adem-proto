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
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/adem-wg/adem-proto/pkg/args"
	"github.com/adem-wg/adem-proto/pkg/tokens"
	"github.com/adem-wg/adem-proto/pkg/util"
	"github.com/adem-wg/adem-proto/pkg/vfy"
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

func loadTokensDNS() ([][]byte, error) {
	if records, err := net.LookupTXT(args.AssetDomainName); err != nil {
		return nil, err
	} else {
		tokens := map[string][]string{}
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
					return nil, err
				} else {
					tokens[tokenId] = util.Insert(tokens[tokenId], partInt, match[tokenGroup])
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
		return bytesTokens, nil
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
	var err error
	if args.AssetDomainName != "" {
		ts, err = loadTokensDNS()
	} else {
		ts, err = loadTokensLocal()
	}

	if err != nil {
		log.Fatal(err)
	}

	trustedKeys := args.LoadTrustedKeys()
	if trustedKeys.Len() > 0 {
		var err error
		if trustedKeys, err = tokens.SetKIDs(trustedKeys, args.LoadTrustedKeysAlg()); err != nil {
			log.Fatalf("could not set trusted keys KIDs: %s", err)
		}
	}
	vfy.VerifyTokens(ts, trustedKeys).Print()
}
