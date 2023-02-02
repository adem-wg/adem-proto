package io

import (
	"fmt"
	"log"
	"net"
	"sync"

	"github.com/adem-wg/adem-proto/pkg/gen"
	"github.com/adem-wg/adem-proto/pkg/util"
)

// nil reserves an element for the emblem

type emblemServer struct {
	timeout int64
	signer  gen.TokenGenerator
	conn    net.PacketConn
	wg      sync.WaitGroup
	c       chan *net.UDPAddr
}

func (srv *emblemServer) listen() {
	defer srv.wg.Done()
	buf := []byte{}
	for {
		_, addr, err := srv.conn.ReadFrom(buf)
		if err != nil {
			break
		} else if udpAddr, ok := addr.(*net.UDPAddr); !ok {
			log.Print("error: could not cast address to net.UDPAddr")
		} else {
			srv.c <- udpAddr
		}
	}
}

func (srv *emblemServer) respond(withEndorsements [][]byte) {
	defer srv.wg.Done()
	defer srv.conn.Close()

	tokensNum := uint16(len(withEndorsements) + 1)
	tokens := make([]tokenPacket, tokensNum)
	for i, endorsement := range withEndorsements {
		// i+1 because 0 is for the emblem
		tokens[i+1] = PacketForToken(endorsement, tokensNum)
	}

	var seq uint16 = 0
	throttler := util.MkThrottler()
	for addr := range srv.c {
		if addr == nil {
			// channel closed
			break
		}

		log.Printf("received request from: %s", addr.String())
		if !throttler.CanGo(addr, srv.timeout) {
			log.Printf("throttling: %s", addr.String())
			continue
		} else if _, raw, err := srv.signer.SignToken(); err != nil {
			log.Printf("cannot generate emblem: %s", err)
		} else if raw != nil {
			log.Printf("sending tokens to: %s", addr.String())
			seq++
			tokens[0] = PacketForToken(raw, tokensNum)
			for _, token := range tokens {
				if n, err := srv.conn.WriteTo(token.Prep(seq), addr); err != nil {
					log.Printf("could not send token: %s", err)
				} else if n < len(token) {
					log.Printf("could not send whole token")
				}
			}
		}
	}
}

func EmblemUDPServer(signer gen.TokenGenerator, endorsements [][]byte, port int, timeout int64, c chan *net.UDPAddr, wg *sync.WaitGroup) {
	defer wg.Done()
	// Connection will be closed in server.respond
	conn, err := net.ListenPacket("udp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatalf("could not start server: %s", err)
	}

	server := emblemServer{
		timeout: timeout,
		signer:  signer,
		conn:    conn,
		c:       c,
	}
	server.wg.Add(2)

	go server.listen()
	go server.respond(endorsements)
	server.wg.Wait()
}
