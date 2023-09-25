/*
This tool starts an emblem distribution server. It parses syslog log output from
stdin. Whenever it observes an unknown (or timed out IP address), it sends that
address a set of tokens to a specified port.
*/
package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/adem-wg/adem-proto/pkg/args"
	"github.com/adem-wg/adem-proto/pkg/gen"
	"github.com/adem-wg/adem-proto/pkg/io"
)

func init() {
	args.AddEmblemDistributionArgs()
	args.AddSigningArgs()
}

func catchSIGINT(c chan os.Signal) bool {
	for signal := range c {
		if signal == syscall.SIGINT {
			return true
		}
	}
	return false
}

func main() {
	flag.Parse()

	log.Println("Starting server... Exit with Ctrl+C")

	var endorsements [][]byte
	if es, err := args.LoadEndorsements(); err != nil {
		log.Fatalf("could not load endorsements: %s", err)
	} else {
		endorsements = es
	}

	var wg sync.WaitGroup
	wg.Add(2)

	addrChan := make(chan *net.UDPAddr)
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT)
	var once sync.Once

	go func() {
		// We don't wait for this goroutine as it might never unblock; if the
		// watcher terminates before the user presses Ctrl+C, it (most probably) hit
		// EOF and will thus close the signalChan, which will definitely close the
		// addrChan.
		defer once.Do(func() { close(signalChan) })
		io.WatchSyslog(os.Stdin, args.EmblemPort, addrChan)
	}()
	go func() {
		defer wg.Done()
		defer close(addrChan)
		defer once.Do(func() { close(signalChan) })
		catchSIGINT(signalChan)
	}()

	// Server will terminate when addrChan is closed
	go io.EmblemUDPServer(
		io.MkRefresher(gen.MkEmblemCfg(
			args.LoadPrivateKey(),
			args.LoadAlg(),
			args.LoadClaimsProto(),
			args.LoadLifetime(),
		), args.SafetyWindow),
		endorsements,
		args.EmblemPort,
		args.ThrottleTimeout,
		addrChan,
		&wg,
	)

	wg.Wait()
}
