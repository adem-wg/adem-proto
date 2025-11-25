package vfy

import (
	"errors"
	"log"

	"github.com/adem-wg/adem-proto/pkg/tokens"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

func verifySignedOrganizational(emblem *ADEMToken, endorsements []*ADEMToken, trustedKeys jwk.Set) ([]VerificationResult, *ADEMToken) {
	embIss, embHasIss := emblem.Token.Issuer()
	embKid, embHasKid := emblem.VerificationKey.KeyID()
	if !embHasKid {
		log.Printf("emblem misses verification kid\n")
		return []VerificationResult{INVALID}, nil
	}

	endorsedBy := make(map[string]*ADEMToken)
	for _, endorsement := range endorsements {
		var end bool
		if err := endorsement.Token.Get("end", &end); err != nil {
			if errors.Is(err, jwt.ClaimNotFoundError()) {
				end = false
			} else {
				log.Printf("could not access end claim: %s\n", err)
			}
		}

		if endorsedKid, err := tokens.GetEndorsedKID(endorsement.Token); err != nil {
			log.Printf("could not get endorsed kid: %s\n", err)
			continue
		} else if endIss, _ := endorsement.Token.Issuer(); embIss != endIss {
			continue
		} else if endSub, _ := endorsement.Token.Subject(); embIss != endSub {
			continue
		} else if endorsedKid != embKid && !end {
			continue
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
	for root == nil {
		if verifKid, ok := last.VerificationKey.KeyID(); !ok {
			log.Printf("could not determine verification kid")
			return []VerificationResult{INVALID}, nil
		} else {
			_, ok := trustedKeys.LookupKeyID(verifKid)
			trustedFound = trustedFound || ok

			if endorsing := endorsedBy[verifKid]; endorsing != nil {
				if err := tokens.VerifyConstraints(emblem.Token, endorsing.Token); err != nil {
					log.Printf("emblem does not comply with endorsement constraints: %s\n", err)
					return []VerificationResult{INVALID}, nil
				} else {
					last = endorsing
				}
			} else {
				root = last
			}
		}
	}

	results := []VerificationResult{SIGNED}
	if trustedFound {
		results = append(results, SIGNED_TRUSTED)
	}

	rootLogged := root.Token.Has("log")
	if embHasIss && !rootLogged {
		log.Print("emblem contains issuer but provides no root key commitment")
		return []VerificationResult{INVALID}, nil
	} else if rootLogged {
		results = append(results, ORGANIZATIONAL)
		if rootKid, ok := root.VerificationKey.KeyID(); !ok {
			log.Printf("root endorsements misses kid\n")
			return []VerificationResult{INVALID}, nil
		} else if _, ok := trustedKeys.LookupKeyID(rootKid); ok {
			results = append(results, ORGANIZATIONAL_TRUSTED)
		}
	}
	return results, root
}
