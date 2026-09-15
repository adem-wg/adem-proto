package args

import (
	"encoding/json"
	"flag"
	"log"
	"os"

	"github.com/adem-wg/adem-proto/pkg/tokens"
	"github.com/veraison/go-cose"
)

var alg string
var lifetime int64
var skeyFile string
var protoPath string
var logsPath string
var publicKeyPath string
var publicKeyAlg string

func AddSigningArgs() {
	flag.StringVar(&alg, "alg", "", "signing algorithm")
	flag.Int64Var(&lifetime, "lifetime", 172800, "emblem validity period; will be ignored if proto specifies exp")
	flag.StringVar(&skeyFile, "skey", "", "path to secret key file")
	flag.StringVar(&protoPath, "proto", "", "path to claims prototype")
	flag.StringVar(&logsPath, "logs", "", "path to key commitment information")
}

func AddPublicKeyArgs() {
	flag.StringVar(&publicKeyPath, "pk", "", "path to a PEM key (for endorsements or verification)")
}

func AddPublicKeyAlgArgs() {
	flag.StringVar(&publicKeyAlg, "pk-alg", "", "public key alg (if omitted, will use -alg)")
}

func LoadAlg() cose.Algorithm {
	if a, ok := tokens.ParseAlgorithm(alg); !ok {
		log.Fatalf(`"-alg %s" algorithm not found`, alg)
		return cose.AlgorithmReserved
	} else {
		return a
	}
}

func LoadPKAlgOpt() (cose.Algorithm, bool) {
	if publicKeyAlg == "" {
		return cose.AlgorithmReserved, false
	} else if alg, ok := tokens.ParseAlgorithm(publicKeyAlg); !ok {
		log.Fatalf(`"-pk-alg %s" algorithm not found`, publicKeyAlg)
		return cose.AlgorithmReserved, false
	} else {
		return alg, true
	}
}

func LoadPKAlg() cose.Algorithm {
	if alg, ok := LoadPKAlgOpt(); ok {
		return alg
	} else {
		// Default to private key algorithm
		return LoadAlg()
	}
}

func LoadLifetime() int64 {
	return lifetime
}

func LoadPrivateKey() *cose.Key {
	if ks, err := LoadKeys(skeyFile); err != nil {
		log.Fatalf("could not load skey: %s", err)
		return nil
	} else if len(ks) != 1 {
		log.Fatalf("expected exactly one key in file")
		return nil
	} else {
		for _, key := range ks {
			return key
		}
		panic("unreachable")
	}
}

func LoadClaimsProto() *tokens.Claims {
	if protoPath == "" {
		log.Fatal("no --proto arg")
	}

	data, err := os.ReadFile(protoPath)
	if err != nil {
		log.Fatal(err)
	}
	claimsProto, err := tokens.ParseClaims(data)
	if err != nil {
		log.Fatalf("cannot parse proto file: %s", err)
	}
	return claimsProto
}

func LoadLogs() tokens.Log {
	var logs tokens.Log
	if logsPath == "" {
		return nil
	} else if bs, err := os.ReadFile(logsPath); err != nil {
		log.Fatalf("could not read logs file: %s", err)
		return nil
	} else if err := json.Unmarshal(bs, &logs); err != nil {
		log.Fatalf("could not decode logs JSON: %s", err)
		return nil
	} else {
		return logs
	}
}

func LoadPublicKey() *cose.Key {
	if ks, err := LoadKeys(publicKeyPath); err == ErrEmptyPath {
		return nil
	} else if err != nil {
		log.Fatalf("could not load pk: %s", err)
		return nil
	} else if len(ks) != 1 {
		log.Fatal("too many or too few pk provided in file")
		return nil
	} else {
		for _, key := range ks {
			return key
		}
		panic("unreachable")
	}
}
