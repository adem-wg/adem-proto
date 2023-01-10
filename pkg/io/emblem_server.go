package io

import (
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/adem-wg/adem-proto/pkg/args"
	"github.com/adem-wg/adem-proto/pkg/gen"
)

var emblem []byte
var emblemExp int64 = -1

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
			if emblemExp <= time.Now().Unix()+int64(args.SafetyWindow) {
				var emblemS string
				var err error
				emblemS, emblemExp, err = cfg.Gen()
				if err != nil {
					log.Printf("cannot generate emblem: %s", err)
					continue
				}
				emblem, err = base64.StdEncoding.DecodeString(emblemS)
				if err != nil {
					log.Printf("cannot decode emblem: %s", err)
					continue
				}
			}
			conn.WriteTo(emblem, addr)
		}
		conn.Close()
		localWg.Done()
	}()

	localWg.Wait()
}
