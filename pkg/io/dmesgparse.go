package io

import (
	"bufio"
	"errors"
	"net"
	"os"
	"regexp"
	"strconv"
	"sync"
)

var matcher *regexp.Regexp

func init() {
	matcher = regexp.MustCompile(`\[\s*(\d+\.\d+)\]\s*iptables log:.+SRC=([\d\.:]+).+SPT=(\d+).+DPT=(\d+)`)
}

type IptablesReq struct {
	IP  net.IP
	SPT uint16
	DPT uint16
}

func parseLine(line string) (*IptablesReq, error) {
	match := matcher.FindStringSubmatch(line)
	if match == nil {
		return nil, errors.New("no match")
	}

	spt, err := strconv.ParseUint(match[3], 10, 16)
	if err != nil {
		return nil, err
	}

	dpt, err := strconv.ParseUint(match[4], 10, 16)
	if err != nil {
		return nil, err
	}

	ip := net.ParseIP(match[2])
	if ip == nil {
		return nil, errors.New("invalid IP")
	}

	return &IptablesReq{
		IP:  ip,
		SPT: uint16(spt),
		DPT: uint16(dpt),
	}, nil
}

func WatchDmesg(file *os.File, c chan *IptablesReq, wg *sync.WaitGroup) {
	defer wg.Done()
	reader := bufio.NewReader(file)

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}

		request, err := parseLine(line)
		if err == nil {
			c <- request
		}
	}
}
