/*
This tool converts CBOR arrays of byte strings containing ADEM tokens or COSE
keys to the hexadecimal IHLE RDATA presentation format.
*/
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/adem-wg/adem-proto/pkg/dns"
	"github.com/fxamacker/cbor/v2"
)

func printFile(path string) {
	raw, err := os.ReadFile(path)
	if err != nil {
		log.Printf("cannot read %s: %s", path, err)
		return
	}

	var items [][]byte
	if err := cbor.Unmarshal(raw, &items); err != nil {
		log.Printf("cannot decode %s as a CBOR byte-string array: %s", path, err)
		return
	}
	for _, item := range items {
		if err := dns.ValidateToken(item); err != nil {
			log.Printf("cannot use item from %s: %s", path, err)
			continue
		}
		fmt.Println(hex.EncodeToString(item))
	}
}

func main() {
	flag.Parse()
	if flag.NArg() == 0 {
		flag.PrintDefaults()
		log.Fatal("no input")
	}
	for _, path := range flag.Args() {
		printFile(path)
	}
}
