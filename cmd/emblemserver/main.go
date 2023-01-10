package main

import (
	"fmt"
	"os"

	"github.com/adem-wg/adem-proto/pkg/io"
)

func main() {
	c := make(chan *io.IptablesReq)
	go io.WatchDmesg(os.Stdin, c)
	for req := range c {
		if req != nil {
			fmt.Printf("%+v\n", *req)
		}
	}
}
