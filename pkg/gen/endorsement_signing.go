package gen

import (
	"github.com/adem-wg/adem-proto/pkg/tokens"
	"github.com/veraison/go-cose"
)

func (cfg *EndorsementConfig) SignToken() (*cose.Sign1Message, error) {
	return SignEndorsement(cfg.sk, cfg.proto, cfg.endorse, cfg.lifetime)
}

func SignEndorsement(secretKey *cose.Key, token *tokens.Claims, endorseKey *cose.Key, lifetime int64) (*cose.Sign1Message, error) {
	prepToken(token, lifetime)
	if kid, err := tokens.COSEThumbprint(endorseKey); err != nil {
		return nil, err
	} else {
		token.Key = kid
		return signWithHeaders(token, secretKey)
	}
}
