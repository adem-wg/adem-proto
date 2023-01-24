package vfy

import (
	"errors"

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
	var kid string
	var err error
	jwKey := hs.JWK()
	if jwKey != nil {
		kid, err = util.GetKID(hs.JWK())
	} else {
		kid = hs.KeyID()
	}
	if err != nil {
		return nil, err
	}
	if kid == "" {
		return nil, errors.New("no kid")
	}
	return &ADEMToken{kid, hs, t}, nil
}
