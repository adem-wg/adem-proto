package vfy

import (
	"log"

	"github.com/adem-wg/adem-proto/pkg/tokens"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

func verifyEndorsed(emblem *ADEMToken, root *ADEMToken, endorsements []*ADEMToken, trustedKeys jwk.Set) ([]VerificationResult, []string) {
	issuers := []string{}
	trustedFound := false
	existsEndorsement := false
	for _, endorsement := range endorsements {
		if endorsedKID, err := tokens.GetEndorsedKID(endorsement.Token); err != nil {
			log.Printf("could not not get endorsed kid: %s", err)
			continue
		} else if root.Token.Issuer() != endorsement.Token.Subject() {
			log.Print("endorsement has wrong subject")
			continue
		} else if endorsement.Token.Issuer() == "" {
			log.Print("endorsement has no issuer")
			continue
		} else if end, _ := endorsement.Token.Get("end"); !end.(bool) {
			log.Print("external endorsement is for assets")
			continue
		} else if _, logged := endorsement.Token.Get("log"); !logged {
			log.Print("endorsement misses root key commitment")
			continue
		} else if root.VerificationKey.KeyID() != endorsedKID {
			log.Print("endorsement endorses wrong key")
			continue
		} else if err := tokens.VerifyConstraints(emblem.Token, endorsement.Token); err != nil {
			log.Printf("emblem does not comply with endorsement constraints: %s", err)
			return []VerificationResult{INVALID}, nil
		} else {
			existsEndorsement = true
			issuers = append(issuers, endorsement.Token.Issuer())
			_, ok := trustedKeys.LookupKeyID(endorsement.VerificationKey.KeyID())
			trustedFound = trustedFound || ok
		}
	}

	if existsEndorsement {
		results := []VerificationResult{ENDORSED}
		if trustedFound {
			results = append(results, ENDORSED_TRUSTED)
		}
		return results, issuers
	} else {
		return nil, nil
	}
}
