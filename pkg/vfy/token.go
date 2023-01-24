package vfy

import (
	"github.com/adem-wg/adem-proto/pkg/util"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type ADEMToken struct {
	VerificationKID string
	Headers         jws.Headers
	Token           jwt.Token
}

func MkADEMToken(hs jws.Headers, t jwt.Token) (*ADEMToken, error) {
	kid, err := util.GetKID(hs.JWK())
	if err != nil {
		return nil, err
	}
	return &ADEMToken{kid, hs, t}, nil
}
