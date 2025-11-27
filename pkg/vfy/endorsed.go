package vfy

import (
	"errors"
	"log"

	"github.com/adem-wg/adem-proto/pkg/tokens"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

func verifyEndorsed(emblem ADEMToken, root ADEMToken, endorsements []ADEMToken, trustedKeys jwk.Set) ([]VerificationResult, []string) {
	rootIss, rootHasIss := root.Token.Issuer()
	if !rootHasIss {
		log.Printf("root endorsements misses issuer\n")
		return []VerificationResult{INVALID}, nil
	}

	issuers := []string{}
	trustedFound := false
	existsEndorsement := false
	for _, endorsement := range endorsements {
		var end bool
		var endLog tokens.Log
		if endorsedKID, err := tokens.GetEndorsedKID(endorsement.Token); err != nil {
			log.Printf("could not not get endorsed kid: %s", err)
			continue
		} else if endSub, ok := endorsement.Token.Subject(); !ok {
			log.Printf("ill-formed endorsement: misses sub claim\n")
			continue
		} else if rootIss != endSub {
			continue
		} else if endIss, ok := endorsement.Token.Issuer(); !ok {
			continue
		} else if err := endorsement.Token.Get("end", &end); err != nil {
			if !errors.Is(err, jwt.ClaimNotFoundError()) {
				log.Printf("could not access end claim: %s\n", err)
			}
		} else if !end {
			continue
		} else if err := endorsement.Token.Get("log", &endLog); err != nil {
			if !errors.Is(err, jwt.ClaimNotFoundError()) {
				log.Printf("could not access log claim: %s\n", err)
			}
			continue
		} else if root.VerificationKid != endorsedKID {
			continue
		} else if err := tokens.VerifyConstraints(emblem.Token, endorsement.Token); err != nil {
			log.Printf("emblem does not comply with endorsement constraints: %s", err)
			return []VerificationResult{INVALID}, nil
		} else {
			existsEndorsement = true
			issuers = append(issuers, endIss)
			_, found := trustedKeys.LookupKeyID(endorsement.VerificationKid)
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
		return []VerificationResult{INVALID}, nil
	}
}
