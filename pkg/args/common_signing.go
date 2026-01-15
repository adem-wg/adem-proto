package args

import (
	"encoding/json"
	"flag"
	"log"
	"os"

	"github.com/adem-wg/adem-proto/pkg/tokens"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

var alg string
var lifetime int64
var skeyFile string
var skeyJWK bool
var protoPath string
var logsPath string
var publicKeyPath string
var publicKeyJWK bool
var publicKeyAlg string

func AddSigningArgs() {
	flag.StringVar(&alg, "alg", "", "signing algorithm")
	flag.Int64Var(&lifetime, "lifetime", 172800, "emblem validity period; will be ignored if proto specifies exp")
	flag.StringVar(&skeyFile, "skey", "", "path to secret key file")
	flag.BoolVar(&skeyJWK, "skey-jwk", false, "is the signing key encoded as JWK? Default is PEM")
	flag.StringVar(&protoPath, "proto", "", "path to claims prototype")
	flag.StringVar(&logsPath, "logs", "", "path to key commitment information")
}

func AddPublicKeyArgs() {
	flag.StringVar(&publicKeyPath, "pk", "", "path to key to public keys (for endorsements or verification) either PEM file or JWK set")
	flag.BoolVar(&publicKeyJWK, "pk-jwk", false, "are the keys encoded as JWK? If not set, PEM is assumed.")
	flag.StringVar(&publicKeyAlg, "pk-alg", "", "public key alg (if omitted, will use -alg)")
}

func LoadAlg() jwa.SignatureAlgorithm {
	if a, ok := jwa.LookupSignatureAlgorithm(alg); !ok {
		log.Fatalf(`"-alg %s" algorithm not found`, alg)
		return jwa.NoSignature()
	} else {
		return a
	}
}

func LoadPKAlg() jwa.SignatureAlgorithm {
	if publicKeyAlg == "" {
		return LoadAlg()
	} else if alg, ok := jwa.LookupSignatureAlgorithm(publicKeyAlg); !ok {
		log.Fatalf(`"-pk-alg %s" algorithm not found`, publicKeyAlg)
		return jwa.NoSignature()
	} else {
		return alg
	}
}

func LoadLifetime() int64 {
	return lifetime
}

func LoadPrivateKey() jwk.Key {
	if ks, err := loadKeys(skeyFile, skeyJWK); err != nil {
		log.Fatalf("could not load skey: %s", err)
		return nil
	} else if k, ok := ks.Key(0); !ok {
		log.Fatalf("to little or too many keys in file")
		return nil
	} else {
		return k
	}
}

func LoadClaimsProto() jwt.Token {
	if protoPath == "" {
		log.Fatal("no --proto arg")
	}

	claimsProto, err := jwt.ReadFile(protoPath, jwt.WithVerify(false), jwt.WithValidate(false))
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

func LoadPublicKey() jwk.Key {
	if ks, err := loadKeys(publicKeyPath, publicKeyJWK); err == ErrEmptyPath {
		return nil
	} else if err != nil {
		log.Fatalf("could not load pk: %s", err)
		return nil
	} else if k, ok := ks.Key(0); !ok {
		log.Fatal("too many or too few pk provided in file")
		return nil
	} else {
		return k
	}
}
