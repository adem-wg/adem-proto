package vfy

import (
	"log"

	"github.com/adem-wg/adem-proto/pkg/tokens"
)

func verifyEndorsed(emblem ADEMToken, root ADEMToken, endorsements []ADEMToken, trustedKeys tokens.KeySet) ([]VerificationResult, []string) {
	if root.Token.Iss == "" {
		log.Printf("root endorsements misses issuer\n")
		return []VerificationResult{INVALID}, nil
	}

	issuers := []string{}
	trustedFound := false
	existsEndorsement := false
	for _, endorsement := range endorsements {
		if endorsement.Token.Key == nil {
			continue
		} else if endorsement.Token.Sub == "" {
			log.Printf("ill-formed endorsement: misses sub claim\n")
			continue
		} else if root.Token.Iss != endorsement.Token.Sub {
			continue
		} else if endorsement.Token.Iss == "" {
			continue
		} else if endorsement.Token.End == nil {
			log.Printf("endorsement has no end claim")
		} else if !*endorsement.Token.End {
			continue
		} else if endorsement.Token.Log == nil {
			log.Printf("endorsements require root key commitment")
			continue
		} else if root.VerificationKid != tokens.ThumbprintToString(endorsement.Token.Key) {
			continue
		} else if err := tokens.Valid(emblem.Token, endorsement.Token); err != nil {
			log.Printf("emblem does not comply with endorsement constraints: %s", err)
			return []VerificationResult{INVALID}, nil
		} else {
			existsEndorsement = true
			issuers = append(issuers, endorsement.Token.Iss)
			_, found := trustedKeys[endorsement.VerificationKid]
			trustedFound = trustedFound || found
		}
	}

	if existsEndorsement {
		results := []VerificationResult{ENDORSED}
		if trustedFound {
			results = append(results, ENDORSED_TRUSTED)
		}
		return results, issuers
	} else {
		return []VerificationResult{}, nil
	}
}
