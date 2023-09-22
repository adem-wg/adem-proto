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
	c       chan *net.UDPAddr
}

// Waits for addresses either parsed from dmesg or from incoming UDP packets.
// Sends all incoming addresses an emblem with all endorsements provided as
// arguments.
// Throttles how many tokens it send to each IP address.
func (srv *emblemServer) respond(withEndorsements [][]byte) {
	tokensNum := uint16(len(withEndorsements) + 1)
	tokens := make([]tokenPacket, tokensNum)
	for i, endorsement := range withEndorsements {
		// i+1 because 0 is for the emblem
		tokens[i+1] = PacketForToken(endorsement, tokensNum)
	}

	var seq uint16 = 0
	throttler := util.MkThrottler(srv.timeout)
	for addr := range srv.c {
		if addr == nil {
			// channel closed
			break
		}

		log.Printf("received request from: %s", addr.String())
		if !throttler.CanGo(addr) {
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

// Emblem distributing UDP server. Listens to the given port and to the given
// channel. Sends emblems to every address it receives over the given channel,
// but each address only once per timeout.
func EmblemUDPServer(signer gen.TokenGenerator, endorsements [][]byte, port int, timeout int64, c chan *net.UDPAddr, wg *sync.WaitGroup) {
	defer wg.Done()
	// Connection will be closed in server.respond
	conn, err := net.ListenPacket("udp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatalf("could not start server: %s", err)
	}
	defer conn.Close()

	server := emblemServer{
		timeout: timeout,
		signer:  signer,
		conn:    conn,
		c:       c,
	}

	// Will terminate when c closes
	server.respond(endorsements)
}
