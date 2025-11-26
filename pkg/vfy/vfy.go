package vfy

import (
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/adem-wg/adem-proto/pkg/consts"
	"github.com/adem-wg/adem-proto/pkg/ident"
	"github.com/adem-wg/adem-proto/pkg/tokens"
	"github.com/adem-wg/adem-proto/pkg/util"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

type VerificationResults struct {
	results    []VerificationResult
	protected  []*ident.AI
	issuer     string
	endorsedBy []string
}

func ResultInvalid() VerificationResults {
	return VerificationResults{results: []VerificationResult{INVALID}}
}

func (res VerificationResults) Print() {
	lns := []string{"Verified set of tokens. Results:"}
	resultsStrs := make([]string, 0, len(res.results))
	for _, r := range res.results {
		resultsStrs = append(resultsStrs, r.String())
	}
	lns = append(lns, fmt.Sprintf("- Security levels:    %s", strings.Join(resultsStrs, ", ")))
	if len(res.protected) > 0 {
		assets := make([]string, 0, len(res.protected))
		for _, asset := range res.protected {
			assets = append(assets, asset.String())
		}
		lns = append(lns, fmt.Sprintf("- Protected assets:   %s", strings.Join(assets, ", ")))
	}
	if res.issuer != "" {
		lns = append(lns, fmt.Sprintf("- Issuer of emblem:   %s", res.issuer))
	}
	if len(res.endorsedBy) > 0 {
		lns = append(lns, fmt.Sprintf("- Issuer endorsed by: %s", strings.Join(res.endorsedBy, ", ")))
	}
	log.Print(strings.Join(lns, "\n"))
}

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
	} else if ademT, err := MkADEMToken(km, msg.Signatures()[0], jwtT); err != nil {
		result.err = err
		return
	} else {
		result.token = ademT
	}
}

// Verify a slice of ADEM tokens.
func VerifyTokens(rawTokens [][]byte, trustedKeys jwk.Set) VerificationResults {

	// Early termination for empty rawTokens slice
	if len(rawTokens) == 0 {
		return ResultInvalid()
	}

	// Ensure trustedKeys is non-nil
	if trustedKeys == nil {
		trustedKeys = jwk.NewSet()
	}

	keys := make([]jwk.Key, 0)
	notKeys := make([][]byte, 0, len(rawTokens))
	for _, t := range rawTokens {
		if b64, err := util.B64Dec(t); err != nil {
			notKeys = append(notKeys, t)
		} else if k, err := x509.ParsePKIXPublicKey(b64); err != nil {
			notKeys = append(notKeys, t)
		} else {
			if alg, err := tokens.SignatureAlgForKey(k); err != nil {
				log.Printf("could not determine algorithm for key: %s\n", err)
			} else if jwkKey, err := jwk.Import(k); err != nil {
				log.Printf("could not create JWK from key: %s", err)
			} else if err := jwkKey.Set("alg", alg); err != nil {
				log.Printf("could not set key algorithm: %s\n", err)
			} else if _, err := tokens.SetKID(jwkKey, true); err != nil {
				log.Printf("could not set KID for key: %s", err)
			} else {
				keys = append(keys, jwkKey)
			}
		}
	}

	// We maintain a thread count for termination purposes. It might be that we
	// cannot verify all token's verification key and must cancel verification.
	threadCount := len(notKeys)
	km := NewKeyManager(keys, len(notKeys))
	// Put trusted public keys into key manager. This allows for termination for
	// tokens without issuer.
	for i := range trustedKeys.Len() {
		if k, ok := trustedKeys.Key(i); !ok {
			panic("index out of bounds")
		} else {
			km.put(k)
		}
	}
	results := make(chan *TokenVerificationResult)
	// Start verification threads
	for _, rawToken := range notKeys {
		go vfyToken(rawToken, km, results)
	}

	// Wait until all verification threads obtained a verification key promise.
	km.waitForInit()

	ts := []*ADEMToken{}
	for {
		// [waiting] is the number of unresolved promises in the key manager, i.e.,
		// blocked threads that wait for a verification key.
		// [threadCount] is the number of threads that could still provide
		// a new verification key in the [results] channel.
		// If there are as many waiting threads as threads that could result in a
		// new verification, we miss verification keys and verification will be
		// aborted.
		if waiting := km.waiting(); waiting > 0 && waiting == threadCount {
			km.killListeners()
		} else if result := <-results; result == nil {
			// All threads have terminated
			break
		} else {
			// We got a new non-nil result from <-results, and hence, one thread must
			// have terminated. Decrement the counter accordingly.
			threadCount -= 1
			// Every call to [vfyToken] will write exactly one result. Hence, only
			// close the [results] channel, when all threads have terminated.
			if threadCount == 0 {
				close(results)
			}

			if result.err != nil {
				log.Printf("discarding invalid token: %s", result.err)
			} else {
				ts = append(ts, result.token)
				var k tokens.EmbeddedKey
				if err := result.token.Token.Get("key", &k); err != nil {
					if !errors.Is(err, jwt.ClaimNotFoundError()) {
						log.Printf("Could not access key claim: %s\n", err)
					}
				} else if k.Key == nil {
					log.Printf("marking key as verified")
					km.setVerified(k.Kid)
				} else {
					log.Printf("putting key for: %s\n", k.Kid)
					km.put(*k.Key)
				}
			}
		}
	}

	var emblem *ADEMToken
	var protected tokens.Bearers
	endorsements := []*ADEMToken{}
	for _, t := range ts {
		cty, ok := t.Headers.ContentType()
		if ok && cty == string(consts.EmblemCty) {
			if emblem != nil {
				// Multiple emblems
				log.Print("Token set contains multiple emblems")
				return ResultInvalid()
			} else if err := jwt.Validate(t.Token, jwt.WithValidator(tokens.EmblemValidator)); err != nil {
				log.Printf("Invalid emblem: %s", err)
				return ResultInvalid()
			} else {
				emblem = t
			}

			if err := emblem.Token.Get("bearers", &protected); err != nil {
				if errors.Is(err, jwt.ClaimNotFoundError()) {
					log.Printf("No bearers claim")
				} else {
					log.Printf("Could not access bearers claim: %s", err)
				}
				return ResultInvalid()
			} else if alg, ok := emblem.Headers.Algorithm(); !ok || alg == jwa.NoSignature() {
				return VerificationResults{
					results:   []VerificationResult{UNSIGNED},
					protected: protected,
				}
			}
		} else if ok && cty == string(consts.EndorsementCty) {
			err := jwt.Validate(t.Token, jwt.WithValidator(tokens.EndorsementValidator))
			if err != nil {
				log.Printf("Invalid endorsement: %s", err)
			} else {
				endorsements = append(endorsements, t)
			}
		} else {
			log.Printf("Token has wrong type: %s", cty)
		}
	}

	if emblem == nil {
		log.Print("no emblem found")
		return ResultInvalid()
	}

	vfyResults, root := verifySignedOrganizational(emblem, endorsements, trustedKeys)
	if util.Contains(vfyResults, INVALID) {
		return ResultInvalid()
	}

	var endorsedResults []VerificationResult
	var endorsedBy []string

	if util.Contains(vfyResults, ORGANIZATIONAL) {
		endorsedResults, endorsedBy = verifyEndorsed(emblem, root, endorsements, trustedKeys)
	}

	if util.Contains(endorsedResults, INVALID) {
		return ResultInvalid()
	}

	iss, _ := root.Token.Issuer()
	return VerificationResults{
		results:    append(vfyResults, endorsedResults...),
		issuer:     iss,
		endorsedBy: endorsedBy,
		protected:  protected,
	}
}
