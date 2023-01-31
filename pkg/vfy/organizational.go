package vfy

import (
	"log"

	"github.com/adem-wg/adem-proto/pkg/tokens"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

func verifySignedOrganizational(emblem *ADEMToken, endorsements []*ADEMToken, trustedKeys jwk.Set) ([]VerificationResult, *ADEMToken) {
	endorsedBy := make(map[string]*ADEMToken)
	for _, endorsement := range endorsements {
		kid, err := tokens.GetEndorsedKID(endorsement.Token)
		end, _ := endorsement.Token.Get("end")
		if err != nil {
			log.Printf("could not get endorsed kid: %s\n", err)
			continue
		} else if emblem.Token.Issuer() != endorsement.Token.Issuer() {
			continue
		} else if emblem.Token.Issuer() != endorsement.Token.Subject() {
			continue
		} else if kid != emblem.VerificationKey.KeyID() && !end.(bool) {
			continue
		} else if _, ok := endorsedBy[kid]; ok {
			log.Println("illegal branch in endorsements")
			return []VerificationResult{INVALID}, nil
		} else {
			endorsedBy[kid] = endorsement
		}
	}

	var root *ADEMToken
	trustedFound := false
	last := emblem
	for root == nil {
		_, ok := trustedKeys.LookupKeyID(last.VerificationKey.KeyID())
		trustedFound = trustedFound || ok

		endorsing := endorsedBy[last.VerificationKey.KeyID()]
		if endorsing != nil {
			// TODO: Check constraints
			last = endorsing
		} else {
			root = last
		}
	}

	results := []VerificationResult{SIGNED}
	if trustedFound {
		results = append(results, SIGNED_TRUSTED)
	}

	_, rootLogged := root.Token.Get("log")
	if emblem.Token.Issuer() != "" && !rootLogged {
		return []VerificationResult{INVALID}, nil
	} else if rootLogged {
		results = append(results, ORGANIZATIONAL)
		if _, ok := trustedKeys.LookupKeyID(root.VerificationKey.KeyID()); ok {
			results = append(results, ORGANIZATIONAL_TRUSTED)
		}
	}
	return results, root
}
