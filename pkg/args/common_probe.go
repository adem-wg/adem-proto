package args

import (
	"flag"
	"log"
)

var probeDNS bool

func AddProbeArgs() {
	flag.BoolVar(&probeDNS, "dns", true, "probe DNS TXT records for tokens and keys")
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
