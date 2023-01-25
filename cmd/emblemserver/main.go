package main

import (
	"flag"
	"log"
	"net"
	"os"
	"sync"

	"github.com/adem-wg/adem-proto/pkg/args"
	"github.com/adem-wg/adem-proto/pkg/gen"
	"github.com/adem-wg/adem-proto/pkg/io"
)

func init() {
	args.AddEmblemDistributionArgs()
	args.AddSigningArgs()
}

func main() {
	flag.Parse()

	log.Println("Starting server... Exit with Ctrl+D")

	var wg sync.WaitGroup
	wg.Add(2)
	c := make(chan net.Addr)
	// WatchDmesg will close c
	go io.WatchDmesg(os.Stdin, args.Port, c, &wg)
	go io.EmblemUDPServer(
		&gen.TokenConfig{
			Sk:    args.LoadPrivateKey(),
			Alg:   args.LoadAlg(),
			Proto: args.LoadClaimsProto(),
		},
		args.Port,
		c,
		&wg,
	)

	wg.Wait()
}
