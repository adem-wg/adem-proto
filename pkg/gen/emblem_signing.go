package gen

import (
	"crypto/ecdsa"
	"time"

	"github.com/adem-wg/adem-proto/pkg/args"
	jwt "github.com/golang-jwt/jwt/v4"
)

func GenToken(secretKey *ecdsa.PrivateKey, alg jwt.SigningMethod, skeleton jwt.MapClaims) (string, int64, error) {
	skeleton["nbf"] = time.Now().Unix()
	exp := skeleton["nbf"].(int64) + args.LoadLifetime()
	skeleton["exp"] = exp
	token := jwt.NewWithClaims(alg, skeleton)
	signed, err := token.SignedString(secretKey)
	if err != nil {
		return "", -1, err
	}
	return signed, exp, nil
}
