package vfy

import (
	"log"
	"sync"

	"github.com/adem-wg/adem-proto/pkg/consts"
	"github.com/adem-wg/adem-proto/pkg/util"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type VerificationResult byte

func (vr VerificationResult) String() string {
	switch vr {
	case UNSIGNED:
		return "UNSIGNED"
	case INVALID:
		return "INVALID"
	case SIGNED:
		return "SIGNED"
	case ORGANIZATIONAL:
		return "ORGANIZATIONAL"
	case ENDORSED:
		return "ENDORSED"
	case SIGNED_TRUSTED:
		return "SIGNED_TRUSTED"
	case ORGANIZATIONAL_TRUSTED:
		return "ORGANIZATIONAL_TRUSTED"
	case ENDORSED_TRUSTED:
		return "ENDORSED_TRUSTED"
	default:
		return ""
	}
}

const UNSIGNED VerificationResult = 0
const INVALID VerificationResult = 1
const SIGNED VerificationResult = 2
const ORGANIZATIONAL VerificationResult = 3
const ENDORSED VerificationResult = 4
const SIGNED_TRUSTED VerificationResult = 5
const ORGANIZATIONAL_TRUSTED VerificationResult = 6
const ENDORSED_TRUSTED VerificationResult = 7

func vfyTokenAsync(rawToken []byte, km *keyManager, results chan *ADEMToken, wg *sync.WaitGroup) {
	defer wg.Done()

	msg, err := jws.Parse(rawToken)
	if err != nil {
		return
	}
	jwtT, err := jwt.Parse(rawToken, jwt.WithKeyProvider(km))
	if err != nil {
		return
	}
	k, err := util.GetEndorsedJWK(jwtT)
	if err == nil {
		km.put(k)
	}
	ademT, err := MkADEMToken(msg.Signatures()[0].ProtectedHeaders(), jwtT)
	if err != nil {
		return
	}
	results <- ademT
}

func VerifyTokens(rawTokens [][]byte) []VerificationResult {
	var wg sync.WaitGroup
	wg.Add(len(rawTokens))
	km := NewKeyManager()
	tokens := make(chan *ADEMToken)
	for _, rawToken := range rawTokens {
		go vfyTokenAsync(rawToken, km, tokens, &wg)
	}
	go func() {
		wg.Wait()
		close(tokens)
	}()

	var emblem *ADEMToken
	endorsements := []*ADEMToken{}
	for t := range tokens {
		if t.Headers.ContentType() == string(consts.EmblemCty) {
			if emblem != nil {
				// Multiple emblems
				log.Print("Token set contains multiple emblems")
				return []VerificationResult{INVALID}
			} else if err := jwt.Validate(t.Token, jwt.WithValidator(EmblemValidator)); err != nil {
				log.Printf("Invalid emblem: %s", err)
				return []VerificationResult{INVALID}
			} else if t.Headers.Algorithm() == jwa.NoSignature {
				return []VerificationResult{UNSIGNED}
			} else {
				emblem = t
			}
		} else if t.Headers.ContentType() == string(consts.EndorsementCty) {
			err := jwt.Validate(t.Token, jwt.WithValidator(EndorsementValidator))
			if err != nil {
				log.Printf("Invalid endorsement: %s", err)
			} else {
				endorsements = append(endorsements, t)
			}
		} else {
			log.Printf("Token has wrong type: %s", t.Headers.ContentType())
		}
	}

	if emblem == nil {
		log.Print("no emblem found")
		return []VerificationResult{INVALID}
	}

	results, root := verifySignedOrganizational(emblem, endorsements)
	if util.Contains(results, INVALID) {
		return results
	}

	endorsedResults := verifyEndorsed(root, endorsements)
	return append(results, endorsedResults...)
}
