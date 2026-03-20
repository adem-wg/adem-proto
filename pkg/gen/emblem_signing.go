package gen

import (
	"github.com/adem-wg/adem-proto/pkg/consts"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

func (cfg *EmblemConfig) SignToken() (jwt.Token, []byte, error) {
	return SignEmblem(cfg.sk, cfg.headerKeyJwk, cfg.alg, cfg.proto, cfg.lifetime)
}

func SignEmblem(secretKey jwk.Key, headerKeyJwk bool, alg jwa.SignatureAlgorithm, token jwt.Token, lifetime int64) (jwt.Token, []byte, error) {
	if err := prepToken(token, lifetime); err != nil {
		return nil, nil, err
	}

	compact, err := signWithHeaders(token, consts.EmblemCty, alg, secretKey, headerKeyJwk)
	if err != nil {
		return nil, nil, err
	}
	return token, compact, nil
}
