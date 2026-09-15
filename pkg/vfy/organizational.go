package vfy

import (
	"log"

	"github.com/adem-wg/adem-proto/pkg/tokens"
)

func verifySignedOrganizational(emblem ADEMToken, endorsements []ADEMToken, trustedKeys tokens.KeySet) ([]VerificationResult, *ADEMToken) {
	embIss, embHasIss := emblem.Token.Issuer()
	endorsedBy := make(map[string]ADEMToken)
	for _, endorsement := range endorsements {
		end, ok := endorsement.Token.CWTClaims["end"].(bool)
		if !ok {
			log.Print("could not access end claim")
			continue
		} else if endorsedKid, err := tokens.GetEndorsedKID(endorsement.Token); err != nil {
			log.Printf("could not get endorsed kid: %s\n", err)
			continue
		} else if endIss, _ := endorsement.Token.Issuer(); embIss != endIss {
			continue
		} else if endSub, _ := endorsement.Token.Subject(); embIss != endSub {
			return []VerificationResult{INVALID}, nil
		} else if endorsedKid != emblem.VerificationKid && !end {
			return []VerificationResult{INVALID}, nil
		} else if _, ok := endorsedBy[endorsedKid]; ok {
			log.Println("illegal branch in endorsements")
			return []VerificationResult{INVALID}, nil
		} else {
			endorsedBy[endorsedKid] = endorsement
		}
	}

	var root *ADEMToken
	trustedFound := false
	last := emblem
	visited := map[string]bool{}
	for root == nil {
		if visited[last.VerificationKid] {
			return []VerificationResult{INVALID}, nil
		}
		visited[last.VerificationKid] = true
		if _, ok := trustedKeys.LookupKeyID(last.VerificationKid); ok {
			trustedFound = true
		}

		if endorsing, ok := endorsedBy[last.VerificationKid]; ok {
			if err := tokens.VerifyConstraints(emblem.Token, endorsing.Token); err != nil {
				log.Printf("emblem does not comply with endorsement constraints: %s\n", err)
				return []VerificationResult{INVALID}, nil
			} else {
				last = endorsing
			}
		} else {
			root = &last
		}
	}

	if len(visited) != len(endorsedBy)+1 {
		return []VerificationResult{INVALID}, nil
	}
	results := []VerificationResult{SIGNED}
	if trustedFound {
		results = append(results, SIGNED_TRUSTED)
	}

	if embHasIss {
		if !root.IsEndorsement || root.Token.Log == nil || root.commitment == nil || !root.commitment() {
			log.Print("emblem contains issuer but provides no verified root key commitment")
			return []VerificationResult{INVALID}, nil
		}
		results = append(results, ORGANIZATIONAL)
		if _, ok := trustedKeys.LookupKeyID(root.VerificationKid); ok {
			results = append(results, ORGANIZATIONAL_TRUSTED)
		}
	}
	return results, root
}
