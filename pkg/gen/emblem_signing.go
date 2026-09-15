package gen

import (
	"github.com/adem-wg/adem-proto/pkg/tokens"
	"github.com/veraison/go-cose"
)

func (cfg *EmblemConfig) SignToken() (*cose.Sign1Message, error) {
	return SignEmblem(cfg.sk, cfg.proto, cfg.lifetime)
}

func SignEmblem(secretKey *cose.Key, token *tokens.Claims, lifetime int64) (*cose.Sign1Message, error) {
	prepToken(token, lifetime)
	return signWithHeaders(token, secretKey)
}
