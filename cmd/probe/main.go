/*
This tool probes for ADEM tokens and untrusted verification keys in IHLE
records. Stdout is a CBOR array of byte strings containing the discovered CBOR
objects.
*/
package main

import (
	"flag"
	"log"
	"os"

	"github.com/adem-wg/adem-proto/pkg/args"
	"github.com/adem-wg/adem-proto/pkg/dns"
	"github.com/fxamacker/cbor/v2"
)

func init() {
	args.AddProbeArgs()
}

func main() {
	flag.Parse()
	if !args.ProbeDNS() {
		log.Fatal("no probe mechanisms enabled")
	}
	server, err := args.ProbeDNSServer()
	if err != nil {
		log.Fatalf("could not load DNS resolver: %s", err)
	}
	tokens, err := dns.Lookup(args.LoadProbeTarget(), server)
	if err != nil {
		log.Fatalf("could not probe DNS: %s", err)
	}
	log.Printf("probed %d IHLE record(s) via DNS", len(tokens))
	encoded, err := cbor.Marshal(tokens)
	if err != nil {
		log.Fatalf("could not encode probe results: %s", err)
	}
	if _, err := os.Stdout.Write(encoded); err != nil {
		log.Fatalf("could not write probe results: %s", err)
	}
}
