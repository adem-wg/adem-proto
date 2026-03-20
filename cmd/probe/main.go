/*
This tool probes for ADEM tokens and untrusted verification keys. It currently
supports probing DNS TXT records and writes the discovered material to stdout
as newline-separated tokens followed by a JWK set.
*/
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"regexp"

	"github.com/adem-wg/adem-proto/pkg/args"
)

func init() {
	args.AddProbeArgs()
}

var (
	tokenGroup                = 2
	tokenReg   *regexp.Regexp = regexp.MustCompile(`^adem-token(-.+)?=(.+)`)
	keyGroup                  = 2
	keyReg     *regexp.Regexp = regexp.MustCompile(`^adem-key(-.+)?=(.+)`)
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
			tokens = append(tokens, match[tokenGroup])
		} else if match := keyReg.FindStringSubmatch(record); match != nil {
			tokens = append(tokens, match[keyGroup])
		}
	}

	log.Printf("probed %d token(s) via DNS", len(tokens))
	return tokens, nil
}

func printTokens(tokens []string) {
	for _, token := range tokens {
		if _, err := fmt.Println(token); err != nil {
			log.Fatalf("error printing token: %s", err)
		}
	}
}
