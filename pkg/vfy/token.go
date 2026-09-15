package vfy

import (
	"time"

	"github.com/adem-wg/adem-proto/pkg/tokens"
	"github.com/veraison/go-cose"
)

type ADEMToken struct {
	IsEndorsement   bool
	VerificationKid string
	Token           *tokens.Claims
	commitment      func() bool
}

func VerifierFor(token []byte, key *cose.Key) TokenVerifier {
	return TokenVerifier{Verify: func() (result *ADEMToken, err error) {
		msg, err := tokens.DecodeMessage(token)
		if err != nil {
			return nil, err
		}
		if err := tokens.VerifyMessage(msg, key); err != nil {
			return nil, err
		}
		body, endorsement, err := tokens.DecodeClaims(msg)
		if err != nil {
			return nil, err
		}
		if err := body.ValidateTime(time.Now()); err != nil {
			return nil, err
		}
		kid, err := tokens.CalcKID(key)
		if err != nil {
			return nil, err
		}
		return &ADEMToken{IsEndorsement: endorsement, VerificationKid: kid, Token: body}, nil
	}}
}
