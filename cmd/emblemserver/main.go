package main

import (
	"os"
	"sync"

	"github.com/adem-wg/adem-proto/pkg/io"
)

func main() {
	var wg sync.WaitGroup
	wg.Add(2)
	c := make(chan *io.IptablesReq)
	go io.WatchDmesg(os.Stdin, c, &wg)
	go io.EmblemDispatcher(c, &wg)

	server, _ := io.EmblemUDPServer()
	if server != nil {
		defer server.Close()
	}

	wg.Wait()
}
