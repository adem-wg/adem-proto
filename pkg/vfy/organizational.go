package vfy

import (
	"log"

	"github.com/adem-wg/adem-proto/pkg/tokens"
)

func verifySignedOrganizational(emblem ADEMToken, endorsements []ADEMToken, trustedKeys tokens.KeySet) ([]VerificationResult, *ADEMToken) {
	endorsedBy := make(map[string]ADEMToken)
	for _, endorsement := range endorsements {
		if endorsement.Token.End == nil {
			log.Printf("endorsement has no end claim")
			continue
		} else if endorsement.Token.Key == nil {
			log.Printf("endorsement misses key")
			continue
		} else if endorsement.Token.Iss != emblem.Token.Iss {
			continue
		} else if endorsement.Token.Sub != emblem.Token.Iss { // TODO: Funny combinations of empty strings?
			continue
		} else {
			endorsedKid := tokens.ThumbprintToString(endorsement.Token.Key)
			if emblem.VerificationKid != endorsedKid && !*endorsement.Token.End {
				continue
			} else if _, ok := endorsedBy[endorsedKid]; ok {
				log.Println("illegal branch in endorsements")
				return []VerificationResult{INVALID}, nil
			} else {
				endorsedBy[endorsedKid] = endorsement
			}
		}
	}

	var root *ADEMToken
	trustedFound := false
	last := emblem
	for root == nil {
		if _, ok := trustedKeys[last.VerificationKid]; ok {
			trustedFound = true
		}

		if endorsing, ok := endorsedBy[last.VerificationKid]; ok {
			if err := tokens.Valid(emblem.Token, endorsing.Token); err != nil {
				log.Printf("emblem does not comply with endorsement constraints: %s\n", err)
				return []VerificationResult{INVALID}, nil
			} else {
				last = endorsing
			}
		} else {
			root = &last
		}
	}

	results := []VerificationResult{SIGNED}
	if trustedFound {
		results = append(results, SIGNED_TRUSTED)
	}

	rootLogged := root.Token.Log != nil
	if emblem.Token.Iss != "" && !rootLogged {
		log.Print("emblem contains issuer but provides no root key commitment")
		return []VerificationResult{INVALID}, nil
	} else if rootLogged {
		results = append(results, ORGANIZATIONAL)
		if _, ok := trustedKeys[root.VerificationKid]; ok {
			results = append(results, ORGANIZATIONAL_TRUSTED)
		}
	}
	return results, root
}
