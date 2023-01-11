package gen

import (
	"time"

	"github.com/adem-wg/adem-proto/pkg/args"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type TokenConfig struct {
	Sk    jwk.Key
	Alg   *jwa.SignatureAlgorithm
	Proto jwt.Token
}

func (cfg *TokenConfig) Gen() (jwt.Token, []byte, error) {
	return GenToken(cfg.Sk, cfg.Alg, cfg.Proto)
}

func GenToken(secretKey jwk.Key, alg *jwa.SignatureAlgorithm, token jwt.Token) (jwt.Token, []byte, error) {
	iat := time.Now().Unix()
	if err := token.Set("iat", iat); err != nil {
		return nil, nil, err
	}
	if err := token.Set("nbf", iat); err != nil {
		return nil, nil, err
	}
	if err := token.Set("exp", iat+args.LoadLifetime()); err != nil {
		return nil, nil, err
	}

	compact, err := jwt.Sign(token, jwt.WithKey(*alg, secretKey))
	if err != nil {
		return nil, nil, err
	}
	return token, compact, nil
}
