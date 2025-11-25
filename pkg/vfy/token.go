package vfy

import (
	"errors"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

type ADEMToken struct {
	VerificationKey jwk.Key
	Headers         jws.Headers
	Token           jwt.Token
}

func MkADEMToken(km *keyManager, sig *jws.Signature, t jwt.Token) (*ADEMToken, error) {
	verifKey := km.getVerificationKey(sig).Get()
	if verifKey == nil {
		return nil, errors.New("no verification key")
	}
	return &ADEMToken{verifKey, sig.ProtectedHeaders(), t}, nil
}
