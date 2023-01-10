package io

import (
	"fmt"
	"log"
	"net"
	"sync"
)

const udp_port = uint16(60)

func EmblemUDPServer() (net.PacketConn, error) {
	conn, err := net.ListenPacket("udp", fmt.Sprintf(":%d", udp_port))
	if err != nil {
		return nil, err
	}

	go func() {
		buf := []byte{}
		for {
			_, addr, err := conn.ReadFrom(buf)
			if err != nil {
				continue
			}
			conn.WriteTo([]byte{}, addr)
		}
	}()

	return conn, nil
}

func EmblemDispatcher(c chan *IptablesReq, wg *sync.WaitGroup) {
	defer wg.Done()

	for req := range c {
		if req == nil {
			continue
		}

		if (*req).DPT == udp_port {
			// Will be handled by UDP server
			continue
		}

		log.Printf("%+v\n", *req)
	}
}
