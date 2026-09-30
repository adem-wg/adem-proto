/*
This tool combines CBOR byte-string arrays containing ADEM tokens or COSE keys.
*/
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/fxamacker/cbor/v2"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s file [file ...]\n\n", os.Args[0])
		fmt.Fprintln(flag.CommandLine.Output(), "Bundle files containing ADEM tokens or COSE keys into a CBOR byte-string array written to stdout.")
	}
	flag.Parse()
	if flag.NArg() == 0 {
		flag.Usage()
		log.Fatal("no input")
	}

	items := make([][]byte, 0)
	for _, path := range flag.Args() {
		raw, err := os.ReadFile(path)
		if err != nil {
			log.Fatalf("could not read %s: %s", path, err)
		}
		items = append(items, raw)
	}

	raw, err := cbor.Marshal(items)
	if err != nil {
		log.Fatalf("could not encode bundle: %s", err)
	}
	if _, err := os.Stdout.Write(raw); err != nil {
		log.Fatalf("could not write bundle: %s", err)
	}
}
