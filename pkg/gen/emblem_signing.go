package gen

import (
	"crypto/ecdsa"
	"time"

	"github.com/adem-wg/adem-proto/pkg/args"
	jwt "github.com/golang-jwt/jwt/v4"
)

func GenToken(secretKey *ecdsa.PrivateKey, alg jwt.SigningMethod, skeleton jwt.MapClaims) (string, error) {
	skeleton["nbf"] = time.Now().Unix()
	skeleton["exp"] = skeleton["nbf"].(int64) + args.LoadLifetime()
	token := jwt.NewWithClaims(alg, skeleton)
	return token.SignedString(secretKey)
}
