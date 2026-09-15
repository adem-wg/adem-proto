package gen

import (
	"github.com/adem-wg/adem-proto/pkg/tokens"
	"github.com/veraison/go-cose"
)

func (cfg *EndorsementConfig) SignToken() (*cose.Sign1Message, error) {
	return SignEndorsement(cfg.sk, cfg.proto, cfg.endorse, cfg.lifetime)
}

func SignEndorsement(secretKey *cose.Key, token *tokens.Claims, endorseKid []byte, lifetime int64) (*cose.Sign1Message, error) {
	prepToken(token, lifetime)
	token.Key = endorseKid
	return signWithHeaders(token, secretKey)
}
