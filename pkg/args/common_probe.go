package args

import (
	"errors"
	"flag"
	"log"
	"net"

	"github.com/miekg/dns"
)

var probeDNS bool
var server string

func AddProbeArgs() {
	flag.BoolVar(&probeDNS, "dns", true, "probe DNS IHLE records for tokens and keys")
	flag.StringVar(&server, "server", "", "DNS server to query (default: system resolver)")
}

func LoadProbeTarget() string {
	args := flag.Args()
	if len(args) == 0 {
		log.Fatal("no probe target given (expected positional argument)")
	} else if len(args) > 1 {
		log.Fatalf("too many positional arguments (expected 1 target, got %d)", len(args))
	}
	return args[0]
}

func ProbeDNS() bool { return probeDNS }

func ProbeDNSServer() (string, error) {
	if server == "" {
		config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil {
			return "", err
		}
		if len(config.Servers) == 0 {
			return "", errors.New("no DNS resolver configured")
		}
		return net.JoinHostPort(config.Servers[0], config.Port), nil
	}
	if _, _, err := net.SplitHostPort(server); err == nil {
		return server, nil
	}
	return net.JoinHostPort(server, "53"), nil
}
