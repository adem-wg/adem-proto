package vfy

import (
	"log"

	"github.com/adem-wg/adem-proto/pkg/tokens"
)

func verifyEndorsed(emblem *ADEMToken, root *ADEMToken, endorsements []*ADEMToken, trustedKeys tokens.KeySet) ([]VerificationResult, []string) {
	if root.Token.Iss == "" {
		log.Printf("root endorsements misses issuer\n")
		return []VerificationResult{INVALID}, nil
	}

	issuers := []string{}
	trustedFound := false
	for _, endorsement := range endorsements {
		if endorsement.Token.Key == nil {
			log.Println("WARNING: discarding ill-formed endorsement - misses key claim")
			continue
		} else if endorsement.Token.Sub == "" {
			log.Println("WARNING: discarding ill-formed endorsement - misses sub claim")
			continue
		} else if endorsement.Token.Iss == "" {
			log.Println("WARNING: discarding ill-formed endorsement - misses iss claim")
			continue
		} else if endorsement.Token.End == nil {
			log.Println("WARNING: discarding ill-formed endorsement - misses end claim")
			continue
		} else if !*endorsement.Token.End {
			log.Println("WARNING: discarding ill-formed endorsement - end claim is false")
			continue
		} else if endorsement.Token.Iss == root.Token.Iss {
			// Internal endorsements are handled by organizational validation.
			continue
		} else if endorsement.Token.Sub != root.Token.Iss {
			log.Println("WARNING: discarding ill-formed endorsement - sub claim does not match")
			continue
		} else if endorsement.Token.Log == nil {
			log.Println("WARNING: discarding ill-formed endorsement - misses log claim")
			continue
		} else if rootKid := tokens.ThumbprintToString(endorsement.Token.Key); root.VerificationKid != rootKid {
			log.Printf("WARNING: discarding ill-formed endorsement - endorses wrong key (endorsed: %v, require %v)\n", rootKid, root.VerificationKid)
			continue
		} else if err := tokens.Valid(emblem.Token, endorsement.Token); err != nil {
			log.Printf("emblem does not comply with endorsement constraints: %s", err)
			continue
		} else {
			issuers = append(issuers, endorsement.Token.Iss)
			_, found := trustedKeys[endorsement.VerificationKid]
			trustedFound = trustedFound || found
		}
	}

	if len(issuers) > 0 {
		results := []VerificationResult{ENDORSED}
		if trustedFound {
			results = append(results, ENDORSED_TRUSTED)
		}
		return results, issuers
	} else {
		return []VerificationResult{}, nil
	}
}
