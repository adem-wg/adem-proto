package args

import "flag"

var SafetyWindow int
var Port int

func init() {
	flag.IntVar(&SafetyWindow, "sfty", 600, "how long before expiry should a new emblem be generated?")
	flag.IntVar(&Port, "port", 60, "emblem server port")
}
