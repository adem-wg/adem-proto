package args

import (
	"flag"
	"log"
	"os"
	"path"
	"path/filepath"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

var alg string
var pem bool
var lifetime int64
var skeyFile string
var protoPath string
var endorsementsDir string

func init() {
	flag.StringVar(&alg, "alg", "", "signing algorithm")
	flag.BoolVar(&pem, "pem", true, "false to parse key as JWK")
	flag.Int64Var(&lifetime, "lifetime", 172800, "emblem validity period")
	flag.StringVar(&skeyFile, "skey", "", "path to secret key file")
	flag.StringVar(&protoPath, "proto", "", "path to claims prototype")
	flag.StringVar(&endorsementsDir, "end", "", "path to endorsements")
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

	key, err := jwk.ParseKey(bs, jwk.WithPEM(true))
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

func LoadEndorsements() ([]string, error) {
	if endorsementsDir == "" {
		log.Fatal("no --end arg")
	}

	matches, err := filepath.Glob(endorsementsDir)
	if err != nil {
		log.Fatalf("cannot expand endorsements glob: %s", err)
	}

	endorsements := []string{}
	for _, fpath := range matches {
		switch path.Ext(fpath) {
		case ".jwt":
			bs, err := os.ReadFile(fpath)
			if err != nil {
				log.Printf("could not parse file %s", fpath)
			}
			endorsements = append(endorsements, string(bs))
		}
	}

	return endorsements, nil
}
