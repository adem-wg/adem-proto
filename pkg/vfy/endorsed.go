package vfy

import (
	"log"

	"github.com/adem-wg/adem-proto/pkg/tokens"
	"github.com/adem-wg/adem-proto/pkg/util"
)

func verifyEndorsed(emblem ADEMToken, root ADEMToken, endorsements []ADEMToken, trustedKeys tokens.KeySet) ([]VerificationResult, []string) {
	rootIss, rootHasIss := root.Token.Issuer()
	if !rootHasIss {
		log.Printf("root endorsements misses issuer\n")
		return []VerificationResult{INVALID}, nil
	}

	issuers := []string{}
	trustedFound := false
	existsEndorsement := false
	for _, endorsement := range endorsements {
		end, hasEnd := endorsement.Token.CWTClaims["end"].(bool)
		if endorsedKID, err := tokens.GetEndorsedKID(endorsement.Token); err != nil {
			continue
		} else if endSub, ok := endorsement.Token.Subject(); !ok {
			log.Printf("ill-formed endorsement: misses sub claim\n")
			continue
		} else if rootIss != endSub {
			continue
		} else if endIss, ok := endorsement.Token.Issuer(); !ok || endIss == rootIss {
			continue
		} else if !hasEnd || !end || endorsement.Token.Log == nil {
			continue
		} else if root.VerificationKid != endorsedKID {
			continue
		} else if err := tokens.VerifyConstraints(emblem.Token, endorsement.Token); err != nil {
			log.Printf("emblem does not comply with endorsement constraints: %s", err)
			continue
		} else {
			if endorsement.commitment == nil || !endorsement.commitment() {
				continue
			}
			existsEndorsement = true
			if _, ok := trustedKeys.LookupKeyID(endorsement.VerificationKid); ok {
				trustedFound = true
			}
			if !util.Contains(issuers, endIss) {
				issuers = append(issuers, endIss)
			}

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
