package args

import (
	"crypto/ecdsa"
	"encoding/json"
	"flag"
	"log"
	"os"
	"path"
	"path/filepath"

	jwt "github.com/golang-jwt/jwt/v4"
)

var algs string
var lifetime int64
var skeyFile string
var protoPath string
var endorsementsDir string

func init() {
	flag.StringVar(&algs, "alg", "", "signing algorithm")
	flag.Int64Var(&lifetime, "lifetime", 172800, "emblem validity period")
	flag.StringVar(&skeyFile, "skey", "", "path to secret key file")
	flag.StringVar(&protoPath, "proto", "", "path to claims prototype")
	flag.StringVar(&endorsementsDir, "end", "", "path to endorsements")
}

func LoadAlg() jwt.SigningMethod {
	if algs == "" {
		log.Fatal("no --alg arg")
	}
	if algs != "ES512" {
		log.Fatal("unsupported --alg")
	}
	alg := jwt.GetSigningMethod(algs)
	if alg == nil {
		log.Fatal("alg does not exist")
	}
	return alg
}

func LoadLifetime() int64 {
	return lifetime
}

func LoadPrivateKey() *ecdsa.PrivateKey {
	if skeyFile == "" {
		log.Fatal("no --skey arg")
	}

	bs, err := os.ReadFile(skeyFile)
	if err != nil {
		log.Fatalf("cannot read key file: %s", err)
	}

	key, err := jwt.ParseECPrivateKeyFromPEM(bs)
	if err != nil {
		log.Fatalf("cannot parse key: %s", err)
	}
	return key
}

type ClaimsProto = map[string]interface{}

func LoadClaimsProto() ClaimsProto {
	if protoPath == "" {
		log.Fatal("no --proto arg")
	}

	bs, err := os.ReadFile(protoPath)
	if err != nil {
		log.Fatalf("cannot read proto file: %s", err)
	}
	var claimsProto ClaimsProto
	err = json.Unmarshal(bs, &claimsProto)
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
