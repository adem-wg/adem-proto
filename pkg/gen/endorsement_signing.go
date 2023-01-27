package gen

import (
	"github.com/adem-wg/adem-proto/pkg/args"
	"github.com/adem-wg/adem-proto/pkg/consts"
	"github.com/adem-wg/adem-proto/pkg/tokens"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

func (cfg *TokenConfig) GenEndorsement() (jwt.Token, []byte, error) {
	return nil, []byte{}, nil
}

func SignEndorsement(secretKey jwk.Key, signingAlg *jwa.SignatureAlgorithm, token jwt.Token, endorseKey jwk.Key, pkAlg *jwa.SignatureAlgorithm) (jwt.Token, []byte, error) {
	if err := prepToken(token, args.LoadLifetime()); err != nil {
		return nil, nil, err
	}

	endorseKey, err := endorseKey.PublicKey()
	if err != nil {
		return nil, nil, err
	} else if err := endorseKey.Set("alg", pkAlg.String()); err != nil {
		return nil, nil, err
	} else if err := tokens.SetKID(endorseKey); err != nil {
		return nil, nil, err
	}
	token.Set("key", endorseKey)

	compact, err := signWithHeaders(token, consts.EndorsementCty, signingAlg, secretKey)
	if err != nil {
		return nil, nil, err
	}
	return token, compact, nil
}
