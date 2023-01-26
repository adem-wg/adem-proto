package args

import (
	"flag"
)

var CTProviderGoogle bool
var CTProviderApple bool
var OI string

func AddVerificationArgs() {
	flag.BoolVar(&CTProviderGoogle, "google", true, "trust CT logs known to Google")
	flag.BoolVar(&CTProviderGoogle, "apple", true, "trust CT logs known to Apple")
	flag.StringVar(&OI, "oi", "", "oi")
}
