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
	return t != nil && t.Token.Key != nil
}

func (t *ADEMToken) IsRootEndorsement() bool {
	return t.IsEndorsement() && t.Token.Log != nil
}

func (t *ADEMToken) IsEmblem() bool {
	return t != nil && t.Token.Assets != nil
}

func Verify(msg *cose.Sign1Message, kid string, key *cose.Key) (*ADEMToken, error) {
	if claims, err := tokens.DecodePayload(msg.Payload); err != nil {
		return nil, err
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
}
