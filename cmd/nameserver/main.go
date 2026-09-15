// nameserver serves a single owner name on local UDP and TCP for IHLE testing.
package main

import (
	"flag"
	"log"
	"net"
	"os"

	"github.com/adem-wg/adem-proto/pkg/discovery"
	"github.com/adem-wg/adem-proto/pkg/tokens"
	"github.com/miekg/dns"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8053", "UDP and TCP listen address")
	name := flag.String("name", "example.test", "owner name")
	path := flag.String("records", "", "file of uppercase hex IHLE RDATA, one per line (default stdin)")
	addr := flag.String("address", "127.0.0.1", "A or AAAA response address")
	rrtype := flag.Uint("ihle-type", uint(discovery.DefaultType), "experimental IHLE RR type")
	ttl := flag.Uint("ttl", 60, "record TTL in seconds")
	flag.Parse()
	if *rrtype < 65280 || *rrtype > 65534 {
		log.Fatal("ihle-type must be in the private-use range 65280..65534")
	}
	if uint64(*ttl) > 0xffffffff {
		log.Fatal("TTL out of range")
	}
	ip := net.ParseIP(*addr)
	if ip == nil {
		log.Fatal("invalid address")
	}
	f := os.Stdin
	if *path != "" {
		var err error
		f, err = os.Open(*path)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
	}
	records, err := tokens.ReadText(f)
	if err != nil {
		log.Fatal(err)
	}
	h, err := discovery.NewHandler(*name, dns.ClassINET, uint16(*rrtype), uint32(*ttl), records, ip)
	if err != nil {
		log.Fatal(err)
	}
	tcp, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	defer tcp.Close()
	udp, err := net.ListenPacket("udp", tcp.Addr().String())
	if err != nil {
		log.Fatal(err)
	}
	defer udp.Close()
	failures := make(chan error, 2)
	go func() { failures <- (&dns.Server{Listener: tcp, Net: "tcp", Handler: h}).ActivateAndServe() }()
	go func() { failures <- (&dns.Server{PacketConn: udp, Net: "udp", Handler: h}).ActivateAndServe() }()
	log.Printf("serving %s IHLE (TYPE%d) on %s over UDP and TCP", h.Name, h.Type, tcp.Addr())
	log.Fatal(<-failures)
}
