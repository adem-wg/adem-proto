package gen

import (
	"crypto/ecdsa"
	"time"

	"github.com/adem-wg/adem-proto/pkg/args"
	jwt "github.com/golang-jwt/jwt/v4"
)

type TokenConfig struct {
	Sk    *ecdsa.PrivateKey
	Alg   jwt.SigningMethod
	Proto jwt.MapClaims
}

func (cfg *TokenConfig) Gen() (string, int64, error) {
	return GenToken(cfg.Sk, cfg.Alg, cfg.Proto)
}

func GenToken(secretKey *ecdsa.PrivateKey, alg jwt.SigningMethod, proto jwt.MapClaims) (string, int64, error) {
	proto["nbf"] = time.Now().Unix()
	exp := proto["nbf"].(int64) + args.LoadLifetime()
	proto["exp"] = exp
	token := jwt.NewWithClaims(alg, proto)
	signed, err := token.SignedString(secretKey)
	if err != nil {
		return "", -1, err
	}
	return signed, exp, nil
}
