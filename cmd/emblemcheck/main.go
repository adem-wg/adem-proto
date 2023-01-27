package main

import (
	"bufio"
	"flag"
	"io"
	"log"
	"os"

	"github.com/adem-wg/adem-proto/pkg/args"
	"github.com/adem-wg/adem-proto/pkg/roots"
	"github.com/adem-wg/adem-proto/pkg/vfy"
)

func init() {
	args.AddVerificationArgs()
}

func main() {
	flag.Parse()
	if !args.CTProviderGoogle && !args.CTProviderApple {
		log.Fatalf("no trusted CT log providers selected")
	} else if err := roots.FetchGoogleKnownLogs(); err != nil {
		log.Fatalf("could not fetch Google known CT logs: %s", err)
	} else if err := roots.FetchAppleKnownLogs(); err != nil {
		log.Fatalf("could not fetch Apple known CT logs: %s", err)
	}

	reader := bufio.NewReader(os.Stdin)
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

	verificationResults := vfy.VerifyTokens(lines)
	log.Print(verificationResults)
}
