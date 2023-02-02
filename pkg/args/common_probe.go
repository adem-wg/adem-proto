package args

import (
	"flag"
	"log"
	"net"
)

var probeAddrStr string
var ProbeTimeout int64
var ProbePort int

func AddProbeArgs() {
	flag.StringVar(&probeAddrStr, "probe", "", "which address to probe?")
	flag.Int64Var(&ProbeTimeout, "timeout", 10, "how many seconds to wait for UDP packets?")
	flag.IntVar(&ProbePort, "port", 60, "UDP port for listening")
}

func LoadProbeAddr() *net.UDPAddr {
	if probeAddrStr == "" {
		log.Fatal("no probe address given")
	}
	addr, err := net.ResolveUDPAddr("udp", probeAddrStr)
	if err != nil {
		log.Fatalf("could not parse probe address: %s", err)
	}
	return addr
}
