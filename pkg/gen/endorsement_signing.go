package gen

import (
	"github.com/adem-wg/adem-proto/pkg/tokens"
	"github.com/veraison/go-cose"
)

func (cfg *EndorsementConfig) SignToken() (*tokens.Claims, []byte, error) {
	return SignEndorsement(cfg.sk, cfg.alg, cfg.proto, cfg.endorse, cfg.endorseAlg, cfg.lifetime)
}

func SignEndorsement(secretKey *cose.Key, signingAlg cose.Algorithm, token *tokens.Claims, endorseKey *cose.Key, pkAlg cose.Algorithm, lifetime int64) (*tokens.Claims, []byte, error) {
	if err := prepToken(token, lifetime); err != nil {
		return nil, nil, err
	}

	endorseKey, err := tokens.WithAlgorithm(endorseKey, pkAlg)
	if err != nil {
		return nil, nil, err
	}
	kid, err := tokens.CalcKID(endorseKey)
	if err != nil {
		return nil, nil, err
	}
	rawKid, err := tokens.KIDBytes(kid)
	if err != nil {
		return nil, nil, err
	}
	token.CWTClaims["key"] = rawKid

	compact, err := signWithHeaders(token, true, signingAlg, secretKey)
	if err != nil {
		return nil, nil, err
	}
	return token, compact, nil
}
