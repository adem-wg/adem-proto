package vfy

import (
	"github.com/adem-wg/adem-proto/pkg/consts"
	"github.com/adem-wg/adem-proto/pkg/tokens"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

type ADEMToken struct {
	IsEndorsement   bool
	VerificationKid string
	Token           jwt.Token
}

func VerifierFor(token []byte, key jwk.Key) TokenVerifier {
	return TokenVerifier{
		Verify: func() (*ADEMToken, error) {
			if alg, ok := key.Algorithm(); !ok {
				return nil, ErrNoAlgFound
			} else if kid, err := tokens.GetKID(key); err != nil {
				return nil, err
			} else if payload, err := jws.Verify(token, jws.WithKey(alg, key)); err != nil {
				return nil, err
			} else if msg, err := jws.Parse(token); err != nil {
				return nil, err
			} else if len(msg.Signatures()) != 1 {
				return nil, ErrTokenNonCompact
			} else if body, err := jwt.Parse(payload, jwt.WithVerify(false)); err != nil {
				return nil, err
			} else {
				headers := msg.Signatures()[0].ProtectedHeaders()
				var isEndorsement bool
				if cty, ok := headers.ContentType(); !ok {
					return nil, ErrCty
				} else if cty == string(consts.EmblemCty) {
					isEndorsement = false
					if err := jwt.Validate(body, jwt.WithValidator(tokens.EmblemValidator)); err != nil {
						return nil, err
					}
				} else if cty == string(consts.EndorsementCty) {
					isEndorsement = true
					if err := jwt.Validate(body, jwt.WithValidator(tokens.EndorsementValidator)); err != nil {
						return nil, err
					}
				} else {
					return nil, ErrCty
				}

				return &ADEMToken{isEndorsement, kid, body}, nil
			}
		},
	}
}
