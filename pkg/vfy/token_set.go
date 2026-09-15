package vfy

import (
	"github.com/adem-wg/adem-proto/pkg/roots"
	"github.com/adem-wg/adem-proto/pkg/tokens"
	"github.com/veraison/go-cose"
)

type TokenVerifier struct{ Verify func() (*ADEMToken, error) }

type TokenSet struct {
	DisableCT   bool
	keyMaterial tokens.KeySet
	results     []ADEMToken
}

func NewTokenSet(keyMaterial tokens.KeySet) TokenSet {
	return TokenSet{keyMaterial: keyMaterial}
}

// Signature and time failures discard only the affected token. Commitment
// checks belong to organizational/endorsed validation, not this filtering step.
func (th *TokenSet) AddToken(raw []byte) error {
	msg, err := tokens.DecodeMessage(raw)
	if err != nil {
		return err
	}
	kid := tokens.KIDText(msg.Headers.Protected[cose.HeaderLabelKeyID].([]byte))
	key, ok := th.keyMaterial.LookupKeyID(kid)
	if !ok {
		return ErrNoKeyFound
	}
	token, err := VerifierFor(raw, key).Verify()
	if err != nil {
		return err
	}
	token.commitment = func() bool {
		if th.DisableCT {
			return false
		}
		iss, ok := token.Token.Issuer()
		if !ok {
			return false
		}
		logs := token.Token.Log
		if len(logs) == 0 {
			return false
		}
		for _, result := range roots.VerifyBindingCerts(iss, key, logs) {
			if result.Ok {
				return true
			}
		}
		return false
	}
	th.results = append(th.results, *token)
	return nil
}

func (th *TokenSet) Verify(_ tokens.KeySet) ([]ADEMToken, []error) {
	return th.results, nil
}
