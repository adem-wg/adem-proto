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

// Verify an ADEM token's signature. Designed to be called asynchronously.
// Results will be returned to the [results] channel. Verification keys will be
// obtained from [km].
// Every call to [vfyToken] will write to [results] exactly once.
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

// Verify a slice of ADEM tokens.
func VerifyTokens(rawTokens [][]byte) []VerificationResult {
	// We maintain a thread count for termination purposes. It might be that we
	// cannot verify all token's verification key and must cancel verification.
	// While [threadCount] is thread-safe, it will be only accessed within this
	// function.
	threadCount := util.NewThreadCount(len(rawTokens))
	km := NewKeyManager(len(rawTokens))
	results := make(chan *TokenVerificationResult)
	// Start verification threads
	for _, rawToken := range rawTokens {
		go vfyToken(rawToken, km, results)
	}

	// Wait until all verification threads obtained a verification key promise.
	km.waitForInit()

	ts := []*ADEMToken{}
	for {
		// [waiting] is the number of unresolved promises in the key manager, i.e.,
		// blocked threads that wait for a verification key.
		// [threadCount.Running()] is the number of threads that could still provide
		// a new verification key in the [results] channel.
		// If there are as many waiting threads as threads that could result in a
		// new verification, we miss verification keys and verification will be
		// aborted.
		if waiting := km.waiting(); waiting > 0 && waiting == threadCount.Running() {
			km.killListeners()
		} else if result := <-results; result == nil {
			// All threads have terminated
			break
		} else {
			// We got a new non-nil result from <-results, and hence, one thread must
			// have terminated. Decrement the counter accordingly.
			threadCount.Done()
			// Every call to [vfyToken] will write exactly one result. Hence, only
			// close the [results] channel, when all threads have terminated.
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

	// Wait for all threads to terminate. This is technically redundant, as we
	// can only be here when nil was read from the [results] channel, which can
	// only happen when the channel was closed, which can only happen when
	// [threadCount.Running() == 0], however, we keep this line as a safeguard
	// for future changes.
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
