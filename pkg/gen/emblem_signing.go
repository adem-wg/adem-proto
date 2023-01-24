package gen

import (
	"github.com/adem-wg/adem-proto/pkg/args"
	"github.com/adem-wg/adem-proto/pkg/consts"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

func (cfg *TokenConfig) GenEmblem() (jwt.Token, []byte, error) {
	return SignEmblem(cfg.Sk, cfg.Alg, cfg.Proto)
}

func SignEmblem(secretKey jwk.Key, alg *jwa.SignatureAlgorithm, token jwt.Token) (jwt.Token, []byte, error) {
	if err := prepToken(token, args.LoadLifetime()); err != nil {
		return nil, nil, err
	}

	compact, err := signWithHeaders(token, consts.EmblemCty, alg, secretKey)
	if err != nil {
		return nil, nil, err
	}
	return token, compact, nil
}
