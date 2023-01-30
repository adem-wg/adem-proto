package args

import (
	"flag"
	"log"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

var CTProviderGoogle bool
var CTProviderApple bool
var OI string
var EI string
var trustedKeyPath string
var trustedKeyPEM bool
var trustedKeyAlg string

func AddVerificationArgs() {
	flag.BoolVar(&CTProviderGoogle, "google", true, "trust CT logs known to Google")
	flag.BoolVar(&CTProviderGoogle, "apple", true, "trust CT logs known to Apple")
	flag.StringVar(&OI, "oi", "", "oi")
	flag.StringVar(&EI, "ei", "", "ei")
	flag.StringVar(&trustedKeyPath, "trusted-pk", "", "path to trusted public key(s)")
	flag.BoolVar(&trustedKeyPEM, "trusted-pk-pem", true, "is the trusted key encoded as PEM?")
	flag.StringVar(&trustedKeyAlg, "trusted-pk-alg", "", "algorithm of trusted public keys")
}

func LoadTrustedKeys() jwk.Set {
	if trustedKeyPath == "" {
		return jwk.NewSet()
	}

	if ks, err := loadKeys(trustedKeyPath, trustedKeyPEM); err != nil {
		log.Fatalf("could not load trusted keys: %s", err)
		return nil
	} else {
		return ks
	}
}

func LoadTrustedKeysAlg() *jwa.SignatureAlgorithm {
	if alg, err := loadAlgByString(trustedKeyAlg); err != nil {
		log.Fatalf("no algorithm found: %s", err)
		return nil
	} else {
		return alg
	}
}
