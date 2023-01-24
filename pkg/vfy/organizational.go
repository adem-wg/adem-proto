package vfy

import (
	"log"

	"github.com/adem-wg/adem-proto/pkg/util"
)

func verifySignedOrganizational(emblem *ADEMToken, endorsements []*ADEMToken) ([]VerificationResult, *ADEMToken) {
	endorsedBy := make(map[string]*ADEMToken)
	for _, endorsement := range endorsements {
		kid, err := util.GetEndorsedKID(endorsement.Token)
		end, _ := endorsement.Token.Get("end")
		if err != nil {
			log.Printf("could not get endorsed kid: %s\n", err)
			continue
		} else if emblem.Token.Issuer() != endorsement.Token.Issuer() {
			continue
		} else if emblem.Token.Issuer() != endorsement.Token.Subject() {
			continue
		} else if kid != emblem.VerificationKID && !end.(bool) {
			continue
		} else if _, ok := endorsedBy[kid]; ok {
			log.Println("illegal branch in endorsements")
			return []VerificationResult{INVALID}, nil
		} else {
			endorsedBy[kid] = endorsement
		}
	}

	var root *ADEMToken
	last := emblem
	for root == nil {
		endorsing := endorsedBy[last.VerificationKID]
		if endorsing != nil {
			// TODO: Check constraints
			last = endorsing
		} else {
			root = last
		}
	}

	results := []VerificationResult{SIGNED}
	_, rootLogged := root.Token.Get("log")
	if emblem.Token.Issuer() != "" && !rootLogged {
		return []VerificationResult{INVALID}, nil
	} else if rootLogged {
		// TODO: Check log configuration
		results = append(results, ORGANIZATIONAL)
	}
	return results, root
}
