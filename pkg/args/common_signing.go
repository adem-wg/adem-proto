package args

import (
	"flag"
	"log"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

var alg string
var lifetime int64
var skeyFile string
var skeyPEM bool
var protoPath string
var publicKeyPath string
var publicKeyPEM bool
var publicKeyAlg string
var SetVerifyJWK bool

func AddSigningArgs() {
	flag.StringVar(&alg, "alg", "", "signing algorithm")
	flag.Int64Var(&lifetime, "lifetime", 172800, "emblem validity period")
	flag.StringVar(&skeyFile, "skey", "", "path to secret key file")
	flag.BoolVar(&skeyPEM, "skey-pem", true, "secret key is PEM")
	flag.StringVar(&protoPath, "proto", "", "path to claims prototype")
	flag.BoolVar(&SetVerifyJWK, "set-jwk", false, "true to include verification key in header")
}

func AddPublicKeyArgs() {
	flag.StringVar(&publicKeyPath, "pk", "", "path to key to public key (for endorsements or verification)")
	flag.BoolVar(&publicKeyPEM, "pk-pem", true, "public key is PEM")
	flag.StringVar(&publicKeyAlg, "pk-alg", "", "public key alg (if omitted, will use -alg)")
}

func LoadAlg() *jwa.SignatureAlgorithm {
	if a, err := loadAlgByString(alg); err != nil {
		log.Fatalf("no algorithm found: %s", err)
		return nil
	} else {
		return a
	}
}

func LoadPKAlg() *jwa.SignatureAlgorithm {
	if alg, err := loadAlgByString(publicKeyAlg); err == ErrNoAlg {
		return LoadAlg()
	} else if err != nil {
		log.Fatalf("no algorithm found: %s", err)
		return nil
	} else {
		return alg
	}
}

func LoadLifetime() int64 {
	return lifetime
}

func LoadPrivateKey() jwk.Key {
	if ks, err := loadKeys(skeyFile, skeyPEM); err != nil {
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

	claimsProto, err := jwt.ReadFile(protoPath, jwt.WithVerify(false))
	if err != nil {
		log.Fatalf("cannot parse proto file: %s", err)
	}
	return claimsProto
}

func LoadPublicKey() jwk.Key {
	if ks, err := loadKeys(publicKeyPath, publicKeyPEM); err == ErrEmptyPath {
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
