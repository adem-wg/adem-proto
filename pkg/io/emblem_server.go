package io

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/adem-wg/adem-proto/pkg/args"
	"github.com/adem-wg/adem-proto/pkg/gen"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

var emblem jwt.Token
var emblemCompact []byte

func EmblemUDPServer(cfg *gen.TokenConfig, port int, c chan net.Addr, wg *sync.WaitGroup) {
	defer wg.Done()
	conn, err := net.ListenPacket("udp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatalf("could not start server: %s", err)
	}

	var localWg sync.WaitGroup
	localWg.Add(2)

	go func() {
		buf := []byte{}
		for {
			_, addr, err := conn.ReadFrom(buf)
			if err != nil {
				break
			}
			c <- addr
		}
		localWg.Done()
	}()

	go func() {
		for addr := range c {
			if emblem.Expiration().Unix() <= time.Now().Unix()+int64(args.SafetyWindow) {
				var err error
				emblem, emblemCompact, err = cfg.Gen()
				if err != nil {
					log.Printf("cannot generate emblem: %s", err)
					continue
				}
			}

			if emblemCompact != nil {
				conn.WriteTo(emblemCompact, addr)
			}
		}
		conn.Close()
		localWg.Done()
	}()

	localWg.Wait()
}
