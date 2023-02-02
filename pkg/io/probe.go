package io

import (
	"fmt"
	"log"
	"net"
	"time"
)

type TokenSet [][]byte
type tokenCounter struct {
	expected  int
	collected [][]byte
}

func responseParser(packetChan chan []byte, resultsChan chan TokenSet) {
	defer close(resultsChan)

	results := make(map[uint16]tokenCounter)
	for p := range packetChan {
		if p == nil {
			break
		} else if seq, total, token, err := FromPacket(p); err != nil {
			log.Printf("could not parse token packet: %s", err)
		} else {
			log.Printf("received token [seq: %d, total: %d, len: %d]", seq, total, len(token))
			counter, ok := results[seq]
			if !ok {
				counter = tokenCounter{expected: total, collected: make([][]byte, 0, total)}
			} else if counter.expected != total {
				log.Printf("packets with same seq differ in total tokens")
				continue
			}

			counter.collected = append(counter.collected, token)
			if len(counter.collected) == counter.expected {
				resultsChan <- counter.collected
				delete(results, seq)
			} else {
				results[seq] = counter
			}
		}
	}
}

func UDPProbe(listenPort int, respondAddr *net.UDPAddr, timeout int64, resultsChan chan TokenSet) {
	laddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", listenPort))
	if err != nil {
		log.Fatalf("could not resolve local address: %s", err)
	}

	conn, err := net.DialUDP("udp", laddr, respondAddr)
	if conn != nil {
		defer conn.Close()
	}
	if err != nil {
		log.Fatalf("could not dial: %s", err)
	}

	if _, err = conn.Write([]byte{}); err != nil {
		log.Fatalf("could not send probe: %s", err)
	} else {
		packetChan := make(chan []byte)
		defer close(packetChan)
		go responseParser(packetChan, resultsChan)

		conn.SetReadDeadline(time.Now().Add(time.Second * time.Duration(timeout)))
		for {
			buff := make([]byte, 4096)
			n, _, err := conn.ReadFromUDP(buff)
			if err != nil {
				log.Printf("connection closed: %s", err)
				break
			} else {
				packetChan <- buff[:n]
			}
		}
	}
}
