package args

import (
	"flag"
	"log"
	"os"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

var alg string
var lifetime int64
var skeyFile string
var skeyPEM bool
var protoPath string
var endorseKeyPath string
var endorseKeyPEM bool
var SetVerifyJWK bool

func init() {
	flag.StringVar(&alg, "alg", "", "signing algorithm")
	flag.Int64Var(&lifetime, "lifetime", 172800, "emblem validity period")
	flag.StringVar(&skeyFile, "skey", "", "path to secret key file")
	flag.BoolVar(&skeyPEM, "skey-pem", true, "secret key is PEM")
	flag.StringVar(&protoPath, "proto", "", "path to claims prototype")
	flag.StringVar(&endorseKeyPath, "endorse", "", "path to key to endorse")
	flag.BoolVar(&endorseKeyPEM, "endorse-pem", true, "endorse key is PEM")
	flag.BoolVar(&SetVerifyJWK, "set-jwk", false, "true to include verification key in header")
}

func LoadAlg() *jwa.SignatureAlgorithm {
	if alg == "" {
		log.Fatal("no --alg arg")
	}
	for _, a := range jwa.SignatureAlgorithms() {
		if a.String() == alg {
			return &a
		}
	}
	log.Fatal("alg does not exist")
	return nil
}

func LoadLifetime() int64 {
	return lifetime
}

func LoadPrivateKey() jwk.Key {
	if skeyFile == "" {
		log.Fatal("no --skey arg")
	}

	bs, err := os.ReadFile(skeyFile)
	if err != nil {
		log.Fatalf("cannot read key file: %s", err)
	}

	key, err := jwk.ParseKey(bs, jwk.WithPEM(skeyPEM))
	if err != nil {
		log.Fatalf("cannot parse key: %s", err)
	}
	return key
}

func LoadClaimsProto() jwt.Token {
	if protoPath == "" {
		log.Fatal("no --proto arg")
	}

	claimsProto, err := jwt.ReadFile(protoPath, jwt.WithVerify(false))
	if err != nil {
		log.Fatalf("cannot parse proto file: %s", err)
	}
	return claimsProto
}

func LoadEndorseKey() jwk.Key {
	if endorseKeyPath == "" {
		return nil
	}

	keySet, err := jwk.ReadFile(endorseKeyPath, jwk.WithPEM(endorseKeyPEM))
	if err != nil {
		log.Fatalf("cannot parse key file: %s", err)
	}

	if keySet.Len() > 1 {
		log.Fatalf("key set provided for endorsement")
	}

	key, ok := keySet.Key(0)
	if !ok {
		log.Fatalf("empty key set provided for endorsement")
	}

	return key
}
