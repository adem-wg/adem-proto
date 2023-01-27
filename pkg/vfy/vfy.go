package vfy

import (
	"errors"
	"log"

	"github.com/adem-wg/adem-proto/pkg/consts"
	"github.com/adem-wg/adem-proto/pkg/tokens"
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

var ErrTokenNonCompact = errors.New("token is not in compact serialization")

type TokenVerificationResult struct {
	token *ADEMToken
	err   error
}

func vfyToken(rawToken []byte, km *keyManager, results chan *TokenVerificationResult) {
	result := TokenVerificationResult{}
	defer func() { results <- &result }()

	jwtT, err := jwt.Parse(rawToken, jwt.WithKeyProvider(km))
	if err != nil {
		result.err = err
		return
	}

	if msg, err := jws.Parse(rawToken); err != nil {
		result.err = err
		return
	} else if len(msg.Signatures()) > 1 {
		result.err = ErrTokenNonCompact
		return
	} else if ademT, err := MkADEMToken(msg.Signatures()[0].ProtectedHeaders(), jwtT); err != nil {
		result.err = err
		return
	} else {
		result.token = ademT
	}
}

func VerifyTokens(rawTokens [][]byte) []VerificationResult {
	threadCount := util.NewThreadCount(len(rawTokens))
	km := NewKeyManager(len(rawTokens))
	results := make(chan *TokenVerificationResult)
	for _, rawToken := range rawTokens {
		go vfyToken(rawToken, km, results)
	}

	km.waitForInit()

	ts := []*ADEMToken{}
	for {
		if waiting := km.waiting(); waiting > 0 && waiting == threadCount.Running() {
			km.killListeners()
		} else if result := <-results; result == nil {
			// All threads terminated
			break
		} else {
			threadCount.Done()
			if threadCount.Running() == 0 {
				close(results)
			}

			if result.err != nil {
				log.Printf("discarding invalid token: %s", result.err)
			} else {
				ts = append(ts, result.token)
				if k, ok := result.token.Token.Get("key"); ok {
					km.put(k.(tokens.EmbeddedKey).Key)
				}
			}
		}
	}

	threadCount.Wait()

	var emblem *ADEMToken
	endorsements := []*ADEMToken{}
	for _, t := range ts {
		if t.Headers.ContentType() == string(consts.EmblemCty) {
			if emblem != nil {
				// Multiple emblems
				log.Print("Token set contains multiple emblems")
				return []VerificationResult{INVALID}
			} else if err := jwt.Validate(t.Token, jwt.WithValidator(tokens.EmblemValidator)); err != nil {
				log.Printf("Invalid emblem: %s", err)
				return []VerificationResult{INVALID}
			} else if t.Headers.Algorithm() == jwa.NoSignature {
				return []VerificationResult{UNSIGNED}
			} else {
				emblem = t
			}
		} else if t.Headers.ContentType() == string(consts.EndorsementCty) {
			err := jwt.Validate(t.Token, jwt.WithValidator(tokens.EndorsementValidator))
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

	vfyResults, root := verifySignedOrganizational(emblem, endorsements)
	if util.Contains(vfyResults, INVALID) {
		return vfyResults
	}

	endorsedResults := verifyEndorsed(root, endorsements)
	return append(vfyResults, endorsedResults...)
}
