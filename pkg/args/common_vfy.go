package args

import (
	"errors"
	"flag"
	"io"
	"log"
	"os"

	"github.com/adem-wg/adem-proto/pkg/roots"
	"github.com/adem-wg/adem-proto/pkg/tokens"
	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

var CTProviderGoogle bool
var CTProviderApple bool
var CTProviderPattern string
var verificationKeyCBORPath string
var verificationKeyPEMPath string
var trustedKeyCBORPath string
var trustedKeyPEMPath string
var tokensFilePath string

func AddCTArgs() {
	flag.BoolVar(&CTProviderGoogle, "google", true, "trust CT logs known to Google")
	flag.BoolVar(&CTProviderApple, "apple", true, "trust CT logs known to Apple")
	flag.StringVar(&CTProviderPattern, "logs", "", "trust CT logs from files")
}

func AddVerificationArgs() {
	flag.StringVar(&verificationKeyCBORPath, "pk-cbor", "", "path to a CBOR array of byte strings containing untrusted COSE verification keys")
	flag.StringVar(&verificationKeyPEMPath, "pk-pem", "", "path to PEM-encoded untrusted verification key(s)")
	flag.StringVar(&trustedKeyCBORPath, "trusted-pk-cbor", "", "path to a CBOR array of byte strings containing trusted COSE keys")
	flag.StringVar(&trustedKeyPEMPath, "trusted-pk-pem", "", "path to PEM-encoded trusted key(s)")
}

func AddVerificationLocalArgs() {
	flag.StringVar(&tokensFilePath, "tokens", "", "file containing a CBOR array of byte strings containing COSE_Sign1 tokens (default: stdin)")
}

func DecodeTokens(reader io.Reader) ([][]byte, error) {
	raw, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	var tokens [][]byte
	if err := cbor.Unmarshal(raw, &tokens); err != nil {
		return nil, err
	}
	return tokens, nil
}

func LoadTokens() [][]byte {
	file := LoadTokensFile()
	if file != os.Stdin {
		defer file.Close()
	}
	tokens, err := DecodeTokens(file)
	if err != nil {
		log.Fatalf("could not decode CBOR token array: %s", err)
	}
	return tokens
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

func LoadTrustedKeys() tokens.KeySet {
	if trustedKeyCBORPath == "" && trustedKeyPEMPath == "" {
		return tokens.KeySet{}
	}

	keys, err := LoadKeys(trustedKeyCBORPath, trustedKeyPEMPath)
	if err != nil {
		log.Fatalf("could not load trusted keys: %s", err)
	}
	if set, err := KeySet(keys); err != nil {
		log.Fatalf("could not prepare trusted keys: %s", err)
		return nil
	} else {
		return set
	}
}

func LoadVerificationKeys() []*cose.Key {
	if verificationKeyCBORPath == "" && verificationKeyPEMPath == "" {
		return nil
	}
	keys, err := LoadKeys(verificationKeyCBORPath, verificationKeyPEMPath)
	if err != nil {
		log.Fatalf("could not load verification keys: %s", err)
	}
	return keys
}

func LoadTokensFile() *os.File {
	if tokensFilePath == "" {
		return os.Stdin
	} else if file, err := os.Open(tokensFilePath); err != nil {
		log.Fatalf("could not open token file: %s", err)
		return nil
	} else {
		return file
	}
}
