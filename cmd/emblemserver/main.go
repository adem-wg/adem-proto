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

	var endorsements [][]byte
	if es, err := args.LoadEndorsements(); err != nil {
		log.Fatalf("could not load endorsements: %s", err)
	} else {
		endorsements = es
	}

	var wg sync.WaitGroup
	wg.Add(2)
	c := make(chan *net.UDPAddr)
	// WatchDmesg will close c
	go io.WatchDmesg(os.Stdin, args.ServerPort, c, &wg)
	go io.EmblemUDPServer(
		io.MkRefresher(gen.MkEmblemCfg(
			args.LoadPrivateKey(),
			args.LoadAlg(),
			args.LoadClaimsProto(),
			args.LoadLifetime(),
		), args.SafetyWindow),
		endorsements,
		args.ServerPort,
		args.ThrottleTimeout,
		c,
		&wg,
	)

	wg.Wait()
}
