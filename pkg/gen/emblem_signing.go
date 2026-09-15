package gen

import (
	"github.com/adem-wg/adem-proto/pkg/tokens"
	"github.com/veraison/go-cose"
)

func (cfg *EmblemConfig) SignToken() (*tokens.Claims, []byte, error) {
	return SignEmblem(cfg.sk, cfg.alg, cfg.proto, cfg.lifetime)
}

func SignEmblem(secretKey *cose.Key, alg cose.Algorithm, token *tokens.Claims, lifetime int64) (*tokens.Claims, []byte, error) {
	if err := prepToken(token, lifetime); err != nil {
		return nil, nil, err
	}

	compact, err := signWithHeaders(token, false, alg, secretKey)
	if err != nil {
		return nil, nil, err
	}
	return token, compact, nil
}
