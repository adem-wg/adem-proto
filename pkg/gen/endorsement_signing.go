package gen

import (
	"github.com/adem-wg/adem-proto/pkg/consts"
	"github.com/adem-wg/adem-proto/pkg/tokens"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

func (cfg *EndorsementConfig) SignToken() (jwt.Token, []byte, error) {
	return SignEndorsement(cfg.sk, cfg.alg, cfg.setJwk, cfg.proto, cfg.endorse, cfg.endorseAlg, cfg.lifetime, cfg.signKid)
}

func SignEndorsement(secretKey jwk.Key, signingAlg *jwa.SignatureAlgorithm, setJwk bool, token jwt.Token, endorseKey jwk.Key, pkAlg *jwa.SignatureAlgorithm, lifetime int64, signKid bool) (jwt.Token, []byte, error) {
	if err := prepToken(token, lifetime); err != nil {
		return nil, nil, err
	}

	endorseKey, err := endorseKey.PublicKey()
	if err != nil {
		return nil, nil, err
	} else if err := endorseKey.Set("alg", pkAlg.String()); err != nil {
		return nil, nil, err
	} else if err := tokens.SetKID(endorseKey, false); err != nil {
		return nil, nil, err
	}

	if kid, err := tokens.GetKID(endorseKey); signKid && err == nil {
		token.Set("key", kid)
	} else if err != nil {
		return nil, nil, err
	} else {
		token.Set("key", endorseKey)
	}

	compact, err := signWithHeaders(token, consts.EndorsementCty, signingAlg, secretKey, setJwk)
	if err != nil {
		return nil, nil, err
	}
	return token, compact, nil
}
