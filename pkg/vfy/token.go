package vfy

import (
	"github.com/adem-wg/adem-proto/pkg/roots"
	"github.com/adem-wg/adem-proto/pkg/tokens"
	"github.com/veraison/go-cose"
)

type ADEMToken struct {
	VerificationKid string
	Token           *tokens.Claims
}

func (t *ADEMToken) IsEndorsement() bool {
	if t == nil {
		return false
	} else {
		return t.Token.Sub != ""
	}
}

func (t *ADEMToken) IsEmblem() bool {
	if t == nil {
		return false
	} else {
		return t.Token.Assets != nil
	}
}

func VerifierFor(msg *cose.Sign1Message, kid string, key *cose.Key) (TokenVerifier, bool) {
	claims, claimsErr := tokens.DecodePayload(msg.Payload)
	vrf := TokenVerifier{
		Verify: func() (*ADEMToken, error) {
			if claimsErr != nil {
				return nil, claimsErr
			} else if vrf, err := key.Verifier(); err != nil {
				return nil, err
			} else if alg, err := msg.Headers.Protected.Algorithm(); err != nil || alg == cose.AlgorithmReserved {
				return nil, ErrNoAlgFound
			} else if err := msg.Verify(nil, vrf); err != nil {
				return nil, err
			} else if false {
				// TODO: check exp/nbf
				return nil, nil
			} else {
				if claims.Log != nil {
					for _, r := range roots.VerifyBindingCerts(claims.Iss, key, claims.Log) {
						if !r.Ok {
							return nil, ErrRootKeyUnbound
						}
					}
				}
				return &ADEMToken{kid, claims}, nil
			}
		},
	}

	return vrf, claims != nil && claims.Log != nil
}
