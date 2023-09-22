package io

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"regexp"
	"sync"
)

// We support syslog messages as specified in https://www.rfc-editor.org/rfc/rfc3164

// Format of syslog event is "<PRI> MM DD TIMESTAMP HOSTNAME MSG"
// <PRI> can be handled by rsyslog (or other processes) already, thus I make this field optional
var syslogParser *regexp.Regexp = regexp.MustCompile(`(<\d{3,5}>)?(\w{3}) (\s\d|\d{2}) (\d\d:\d\d:\d\d) ([^\s]+) (.+)`)

// Format of syslog message *often* is "SERVICE: [DATA] MSG"; we only handle
// messages prefixed by "emblem_server_event:".
var msgGroup int = 6
var syslogMsgParser *regexp.Regexp = regexp.MustCompile(`([^:]+: )?(\[.+\] )?emblem_server_event: (.*)`)

// The data part of the mesasge should contain a SRC=... field that maps to an
// IPv4 or IPv6 field.
var dataGroup int = 3
var ipGroup = 1
var msgDataParser *regexp.Regexp = regexp.MustCompile(`SRC=([\d\.]+|[\d\w:\[\]]+)`)

func parseLine(line string, serverPort int) *net.UDPAddr {
	if syslogMatch := syslogParser.FindStringSubmatch(line); syslogMatch == nil {
		return nil
	} else if msgMatch := syslogMsgParser.FindStringSubmatch(syslogMatch[msgGroup]); msgMatch == nil {
		return nil
	} else if dataMatch := msgDataParser.FindStringSubmatch(msgMatch[dataGroup]); dataMatch == nil {
		return nil
	} else if addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", dataMatch[ipGroup], serverPort)); err != nil || addr.IP.IsLoopback() {
		return nil
	} else {
		return addr
	}
}

func WatchSyslog(file *os.File, serverPort int, c chan *net.UDPAddr, wg *sync.WaitGroup) {
	defer wg.Done()
	defer close(c)
	reader := bufio.NewReader(file)

	for {
		if line, err := reader.ReadString('\n'); err != nil {
			return
		} else if request := parseLine(line, serverPort); request != nil {
			c <- request
		}
	}
}
