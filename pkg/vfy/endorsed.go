package vfy

import (
	"log"

	"github.com/adem-wg/adem-proto/pkg/tokens"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

func verifyEndorsed(root *ADEMToken, endorsements []*ADEMToken, trustedKeys jwk.Set) []VerificationResult {
	trustedFound := false
	existsEndorsement := false
	for _, endorsement := range endorsements {
		endorsedKID, err := tokens.GetEndorsedKID(endorsement.Token)
		if err != nil {
			log.Printf("could not not get endorsed kid: %s\n", err)
			continue
		} else if root.Token.Issuer() != endorsement.Token.Subject() {
			continue
		} else if endorsement.Token.Issuer() == "" {
			continue
		} else if end, _ := endorsement.Token.Get("end"); !end.(bool) {
			continue
		} else if root.VerificationKey.KeyID() != endorsedKID {
			continue
		} else {
			// TODO: Check constraints
			existsEndorsement = true
			_, ok := trustedKeys.LookupKeyID(endorsement.VerificationKey.KeyID())
			trustedFound = trustedFound || ok
		}
	}

	if existsEndorsement {
		results := []VerificationResult{ENDORSED}
		if trustedFound {
			results = append(results, ENDORSED_TRUSTED)
		}
		return results
	} else {
		return []VerificationResult{}
	}
}
