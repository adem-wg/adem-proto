package io

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"sync"
)

var matcher *regexp.Regexp

func init() {
	matcher = regexp.MustCompile(`\[\s*(\d+\.\d+)\]\s*iptables log:.*SRC=([\d\.:]+).*DPT=(\d+)`)
}

func parseLine(line string, serverPort int) net.Addr {
	match := matcher.FindStringSubmatch(line)
	if match == nil {
		return nil
	}

	dpt, err := strconv.ParseInt(match[3], 10, 16)
	// If DPT == serverPort, the server will handle this request
	if err != nil || dpt == int64(serverPort) {
		return nil
	}

	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", match[2], serverPort))
	if err != nil || addr.IP.IsLoopback() {
		return nil
	}
	return addr
}

func WatchDmesg(file *os.File, serverPort int, c chan net.Addr, wg *sync.WaitGroup) {
	defer wg.Done()
	reader := bufio.NewReader(file)

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			close(c)
			return
		}

		request := parseLine(line, serverPort)
		if request != nil {
			c <- request
		}
	}
}
