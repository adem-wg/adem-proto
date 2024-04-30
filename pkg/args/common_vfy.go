package args

import (
	"errors"
	"flag"
	"log"
	"os"

	"github.com/adem-wg/adem-proto/pkg/roots"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

var CTProviderGoogle bool
var CTProviderApple bool
var CTProviderPattern string
var OI string
var trustedKeyPath string
var trustedKeyPEM bool
var trustedKeyAlg string
var tokensFilePath string

func AddCTArgs() {
	flag.BoolVar(&CTProviderGoogle, "google", true, "trust CT logs known to Google")
	flag.BoolVar(&CTProviderApple, "apple", true, "trust CT logs known to Apple")
	flag.StringVar(&CTProviderPattern, "logs", "", "trust CT logs from files")
}

func AddVerificationArgs() {
	flag.StringVar(&OI, "oi", "", "OI to check root key log inclusion")
	flag.StringVar(&trustedKeyPath, "trusted-pk", "", "path to trusted public key(s)")
	flag.BoolVar(&trustedKeyPEM, "trusted-pk-pem", true, "is the trusted key encoded as PEM?")
	flag.StringVar(&trustedKeyAlg, "trusted-pk-alg", "", "algorithm of trusted public keys")
}

func AddVerificationLocalArgs() {
	flag.StringVar(&tokensFilePath, "tokens", "", "file that contains new-line separated tokens (if omitted, will read from stdin)")
}

var ErrNoLogProvider = errors.New("no log providers")

func FetchKnownLogs() error {
	if !CTProviderApple && !CTProviderGoogle && CTProviderPattern == "" {
		return ErrNoLogProvider
	}

	if CTProviderApple {
		if err := roots.FetchAppleKnownLogs(); err != nil {
			return err
		}
	}

	if CTProviderGoogle {
		if err := roots.FetchGoogleKnownLogs(); err != nil {
			return err
		}
	}

	if CTProviderPattern != "" {
		if err := roots.ReadKnownLogs(CTProviderPattern); err != nil {
			return err
		}
	}

	return nil
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

func LoadTokensFile() *os.File {
	if tokensFilePath == "" {
		return os.Stdin
	} else if f, err := os.Open(tokensFilePath); err != nil {
		log.Fatalf("could not open file: %s", err)
		return nil
	} else {
		return f
	}
}
