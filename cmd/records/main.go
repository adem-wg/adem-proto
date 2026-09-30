/*
This tool converts CBOR arrays of byte strings containing ADEM tokens or COSE
keys, or individual CWTs, to the hexadecimal IHLE RDATA presentation format.
*/
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"math"
	"os"

	"github.com/adem-wg/adem-proto/pkg/dns"
	"github.com/fxamacker/cbor/v2"
	mdns "github.com/miekg/dns"
)

var name = flag.String("name", "", "owner name of records")
var ttl = flag.Uint("ttl", 300, "zone record TTL in seconds")

func decodeItems(raw []byte) [][]byte {
	var items [][]byte
	if err := cbor.Unmarshal(raw, &items); err == nil {
		return items
	} else {
		return [][]byte{raw}
	}
}

func tokensToRecords(path string) (records []*mdns.RFC3597) {
	records = []*mdns.RFC3597{}
	raw, err := os.ReadFile(path)
	if err != nil {
		log.Printf("cannot read %s: %s", path, err)
	} else {
		items := decodeItems(raw)
		for _, item := range items {
			rr := mdns.RFC3597{
				Hdr:   mdns.RR_Header{Name: *name, Rrtype: dns.TypeIHLE, Class: mdns.ClassINET, Ttl: uint32(*ttl)},
				Rdata: hex.EncodeToString(item),
			}
			records = append(records, &rr)
		}
	}
	return records
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [flags] file [file ...]\n\n", os.Args[0])
		fmt.Fprintln(flag.CommandLine.Output(), "Convert CBOR bundles or individual CWTs to IHLE records.")
		flag.PrintDefaults()
	}
	flag.Parse()
	if *ttl > math.MaxUint32 {
		log.Fatal("TTL exceeds the maximum DNS TTL value")
	}
	if flag.NArg() == 0 {
		flag.Usage()
		log.Fatal("no input")
	}
	for _, path := range flag.Args() {
		rrs := tokensToRecords(path)
		for _, rr := range rrs {
			fmt.Println(rr.String())
		}
	}
}
