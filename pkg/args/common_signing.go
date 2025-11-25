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
var skeyJWK bool
var protoPath string
var publicKeyPath string
var publicKeyJWK bool
var publicKeyAlg string
var setVerifyJWK bool
var signKid bool
var keysCommand string

func AddSigningArgs() {
	flag.StringVar(&alg, "alg", "", "signing algorithm")
	flag.Int64Var(&lifetime, "lifetime", 172800, "emblem validity period; will be ignored if proto specifies exp")
	flag.StringVar(&skeyFile, "skey", "", "path to secret key file")
	flag.BoolVar(&skeyJWK, "skey-jwk", false, "is the signing key encoded as JWK? Default is PEM")
	flag.StringVar(&protoPath, "proto", "", "path to claims prototype")
	flag.BoolVar(&setVerifyJWK, "set-jwk", false, "true to include verification key in header")
	flag.BoolVar(&signKid, "sign-kid", false, "true to only sign a hash of the key")
}

func AddKeyArgs() {
	flag.StringVar(&keysCommand, "cmd", "", "command to execute ('gen-kid' or 'encode')")
}

func AddPublicKeyArgs() {
	flag.StringVar(&publicKeyPath, "pk", "", "path to key to public keys (for endorsements or verification) either PEM file or JWK set")
	flag.BoolVar(&publicKeyJWK, "pk-jwk", false, "are the keys encoded as JWK? If not set, PEM is assumed.")
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

func LoadSetVerifyJwk() bool {
	return setVerifyJWK
}

func LoadSignKid() bool {
	return signKid
}

func LoadKeysCommand() string {
	return keysCommand
}
