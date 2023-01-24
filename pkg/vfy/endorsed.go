package vfy

import (
	"log"

	"github.com/adem-wg/adem-proto/pkg/util"
)

func verifyEndorsed(root *ADEMToken, endorsements []*ADEMToken) []VerificationResult {
	existsEndorsement := false
	for _, endorsement := range endorsements {
		endorsedKID, err := util.GetEndorsedKID(endorsement.Token)
		if err != nil {
			log.Printf("could not not get endorsed kid: %s\n", err)
			continue
		} else if root.Token.Issuer() != endorsement.Token.Subject() {
			continue
		} else if endorsement.Token.Issuer() == "" {
			continue
		} else if end, _ := endorsement.Token.Get("end"); !end.(bool) {
			continue
		} else if root.VerificationKID != endorsedKID {
			continue
		} else {
			// TODO: Check log setup
			// TODO: Check constraints
			existsEndorsement = true
		}
	}

	if existsEndorsement {
		return []VerificationResult{ENDORSED}
	} else {
		return []VerificationResult{}
	}
}
