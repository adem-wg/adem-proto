package args

import (
	"encoding/json"
	"flag"
	"log"
	"os"

	"github.com/adem-wg/adem-proto/pkg/tokens"
	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

var alg string
var lifetime int64
var skeyCBORFile string
var skeyPEMFile string
var protoPath string
var logsPath string
var publicKeyCBORPath string
var publicKeyPEMPath string

func AddSigningArgs() {
	flag.StringVar(&alg, "alg", "", "COSE signing algorithm (for example ES256)")
	flag.Int64Var(&lifetime, "lifetime", 172800, "token validity period; ignored if the claims specify exp")
	flag.StringVar(&skeyCBORFile, "skey-cbor", "", "path to a CBOR array of private COSE keys")
	flag.StringVar(&skeyPEMFile, "skey-pem", "", "path to a PEM-encoded private key")
	flag.StringVar(&protoPath, "proto", "", "path to a JSON-encoded Claims object")
	flag.StringVar(&logsPath, "logs", "", "path to a CBOR-encoded log claim")
}

func AddPublicKeyArgs() {
	flag.StringVar(&publicKeyCBORPath, "pk-cbor", "", "path to a CBOR array of COSE keys")
	flag.StringVar(&publicKeyPEMPath, "pk-pem", "", "path to a PEM-encoded key")
}

func LoadAlg() cose.Algorithm {
	if algorithm, err := ParseAlgorithm(alg); err != nil {
		log.Fatalf("could not load signing algorithm: %s", err)
		return cose.AlgorithmReserved
	} else {
		return algorithm
	}
}

func LoadLifetime() int64 {
	return lifetime
}

func loadOneKey(cborPath, pemPath string) *cose.Key {
	if keys, err := LoadKeys(cborPath, pemPath); err != nil {
		log.Fatalf("could not load key: %s", err)
		return nil
	} else if len(keys) != 1 {
		log.Fatalf("expected exactly one key, got %d", len(keys))
		return nil
	} else {
		return keys[0]
	}
}

func LoadPrivateKey() *cose.Key {
	key := loadOneKey(skeyCBORFile, skeyPEMFile)
	key.Algorithm = LoadAlg()
	return key
}

func LoadClaimsProto() *tokens.Claims {
	if protoPath == "" {
		log.Fatal("no --proto arg")
	}

	var claims tokens.Claims
	if raw, err := os.ReadFile(protoPath); err != nil {
		log.Fatalf("cannot read claims prototype: %s", err)
	} else if err := json.Unmarshal(raw, &claims); err != nil {
		log.Fatalf("cannot decode JSON claims prototype: %s", err)
	}
	return &claims
}

func LoadLogs() tokens.Log {
	if logsPath == "" {
		return nil
	}

	var logs tokens.Log
	if raw, err := os.ReadFile(logsPath); err != nil {
		log.Fatalf("could not read logs: %s", err)
	} else if err := cbor.Unmarshal(raw, &logs); err != nil {
		log.Fatalf("could not decode CBOR logs: %s", err)
	}
	return logs
}

func LoadPublicKey() *cose.Key {
	if publicKeyCBORPath == "" && publicKeyPEMPath == "" {
		return nil
	}
	key := loadOneKey(publicKeyCBORPath, publicKeyPEMPath)
	publicKey, err := PublicKey(key)
	if err != nil {
		log.Fatalf("could not derive public key: %s", err)
	}
	return publicKey
}
