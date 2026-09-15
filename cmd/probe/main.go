// probe discovers IHLE tokens and untrusted COSE public keys and prints hex RDATA lines.
package main

import (
	"flag"
	"fmt"
	"log"
	"strings"

	"github.com/adem-wg/adem-proto/pkg/args"
	"github.com/adem-wg/adem-proto/pkg/discovery"
	"github.com/adem-wg/adem-proto/pkg/tokens"
	"github.com/miekg/dns"
)

func main() {
	args.AddProbeArgs()
	server := flag.String("server", "", "DNS server host:port (default system resolver)")
	qtype := flag.String("qtype", "IHLE", "query type, e.g. IHLE, A, AAAA, TXT")
	rrtype := flag.Uint("ihle-type", uint(discovery.DefaultType), "experimental IHLE RR type")
	flag.Parse()
	if !args.ProbeDNS() {
		log.Fatal("no probe mechanisms enabled")
	}
	if *rrtype < 65280 || *rrtype > 65534 {
		log.Fatal("ihle-type must be in the private-use range 65280..65534")
	}
	qt := uint16(*rrtype)
	if strings.ToUpper(*qtype) != "IHLE" {
		var ok bool
		qt, ok = dns.StringToType[strings.ToUpper(*qtype)]
		if !ok {
			log.Fatal("unknown qtype")
		}
	}
	records, err := discovery.Probe(args.LoadProbeTarget(), *server, qt, uint16(*rrtype))
	if err != nil {
		log.Fatal(err)
	}
	for _, raw := range records {
		fmt.Println(tokens.Text(raw))
	}
	log.Printf("probed %d IHLE records", len(records))
}
