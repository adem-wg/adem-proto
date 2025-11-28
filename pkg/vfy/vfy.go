package vfy

import (
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/adem-wg/adem-proto/pkg/ident"
	"github.com/adem-wg/adem-proto/pkg/tokens"
	"github.com/adem-wg/adem-proto/pkg/util"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

var ErrNoKeyFound = errors.New("no key found")
var ErrNoAlgFound = errors.New("no alg found")
var ErrCty = errors.New("no or illegal content type")
var ErrRootKeyUnbound = errors.New("root key not properly committed")
var ErrLogsEmpty = errors.New("logs field cannot be empty")
var ErrNoIss = errors.New("issuer claim missing")
var ErrTokenNonCompact = errors.New("token is not in compact serialization")

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

// Verify a slice of ADEM tokens.
func VerifyTokens(rawTokens [][]byte, trustedKeys jwk.Set, untrustedKeys jwk.Set) VerificationResults {

	// Early termination for empty rawTokens slice
	if len(rawTokens) == 0 {
		return ResultInvalid()
	}

	// Ensure trustedKeys is non-nil
	if trustedKeys == nil {
		trustedKeys = jwk.NewSet()
	}

	th := NewTokenSet(untrustedKeys)
	// Put trusted public keys into key manager. This allows for termination for
	// tokens without issuer.
	for i := range trustedKeys.Len() {
		if k, ok := trustedKeys.Key(i); !ok {
			panic("index out of bounds")
		} else {
			th.put(k)
		}
	}

	// Start verification
	for _, rawToken := range rawTokens {
		if err := th.AddToken(rawToken); err != nil {
			log.Printf("could not verify token: %s\n", err)
		}
	}

	th.logErrors()

	var emblem *ADEMToken
	var protected tokens.Bearers
	endorsements := []ADEMToken{}
	for _, t := range th.results {
		if t.IsEndorsement {
			endorsements = append(endorsements, t)
		} else if emblem == nil {
			emblem = &t
		} else {
			// Multiple emblems
			log.Print("Token set contains multiple emblems")
			return ResultInvalid()
		}
	}

	if emblem == nil {
		log.Print("no emblem found")
		return ResultInvalid()
	}

	vfyResults, root := verifySignedOrganizational(*emblem, endorsements, trustedKeys)
	if util.Contains(vfyResults, INVALID) {
		return ResultInvalid()
	}

	var endorsedResults []VerificationResult
	var endorsedBy []string

	if util.Contains(vfyResults, ORGANIZATIONAL) {
		endorsedResults, endorsedBy = verifyEndorsed(*emblem, *root, endorsements, trustedKeys)
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
