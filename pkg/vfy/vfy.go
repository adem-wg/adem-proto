package vfy

import (
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/adem-wg/adem-proto/pkg/ident"
	"github.com/adem-wg/adem-proto/pkg/tokens"
	"github.com/adem-wg/adem-proto/pkg/util"
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

func (res VerificationResults) Valid() bool {
	return len(res.results) > 0 && !util.Contains(res.results, INVALID)
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
	case INVALID:
		return "INVALID"
	case SIGNED:
		return "SIGNED-UNTRUSTED"
	case ORGANIZATIONAL:
		return "ORGANIZATIONAL-UNTRUSTED"
	case ENDORSED:
		return "ENDORSED-UNTRUSTED"
	case SIGNED_TRUSTED:
		return "SIGNED-TRUSTED"
	case ORGANIZATIONAL_TRUSTED:
		return "ORGANIZATIONAL-TRUSTED"
	case ENDORSED_TRUSTED:
		return "ENDORSED-TRUSTED"
	default:
		return ""
	}
}

const INVALID VerificationResult = 1
const SIGNED VerificationResult = 2
const ORGANIZATIONAL VerificationResult = 4
const ENDORSED VerificationResult = 6
const SIGNED_TRUSTED VerificationResult = 3
const ORGANIZATIONAL_TRUSTED VerificationResult = 5
const ENDORSED_TRUSTED VerificationResult = 7

func filterKeys(rawTokens [][]byte) ([][]byte, tokens.KeySet) {
	remaining := make([][]byte, 0)
	keys := tokens.NewKeySet()
	for _, t := range rawTokens {
		if key, err := tokens.DecodePublicCOSEKey(t); err == nil {
			if err := keys.AddKey(key); err != nil {
				log.Printf("could not compute kid: %s", err)
			}
		} else {
			remaining = append(remaining, t)
		}
	}

	return remaining, keys
}

// Verify a slice of ADEM tokens.
func VerifyTokens(rawTokens [][]byte, trustedKeys tokens.KeySet) VerificationResults {
	return VerifyTokensWithCT(rawTokens, trustedKeys, true)
}

func VerifyTokensWithCT(rawTokens [][]byte, trustedKeys tokens.KeySet, allowCT bool) VerificationResults {

	// Early termination for empty rawTokens slice
	if len(rawTokens) == 0 {
		return ResultInvalid()
	}

	// Ensure trustedKeys is non-nil
	if trustedKeys == nil {
		trustedKeys = tokens.NewKeySet()
	}

	normalized, err := tokens.NormalizeKeys(trustedKeys)
	if err != nil {
		return ResultInvalid()
	}
	trustedKeys = normalized
	tokensNoKeys, recordKeys := filterKeys(rawTokens)
	for kid, key := range trustedKeys {
		recordKeys[kid] = key
	}

	th := NewTokenSet(recordKeys)
	th.DisableCT = !allowCT
	for _, rawToken := range tokensNoKeys {
		if err := th.AddToken(rawToken); err != nil {
			log.Printf("could not verify token: %s\n", err)
		}
	}

	verifiedTokens, errs := th.Verify(trustedKeys)

	if len(errs) > 0 {
		log.Printf("encountered the following errors during token verification...")
		for _, err := range errs {
			log.Print(err)
		}
	}

	var emblem *ADEMToken
	var protected tokens.Assets
	endorsements := []ADEMToken{}
	for _, t := range verifiedTokens {
		if t.IsEndorsement {
			endorsements = append(endorsements, t)
		} else if emblem == nil {
			emblem = &t
			var err error
			protected, err = emblem.Token.Assets()
			if err != nil {
				log.Print(err)
				return ResultInvalid()
			}
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
		endorsedResults = nil
		endorsedBy = nil
	}

	iss, _ := root.Token.Issuer()
	return VerificationResults{
		results:    strongest(append(vfyResults, endorsedResults...)),
		issuer:     iss,
		endorsedBy: endorsedBy,
		protected:  protected,
	}
}

// Return the strongest trusted result and any strictly stronger untrusted result.
func strongest(results []VerificationResult) []VerificationResult {
	var trusted, untrusted VerificationResult
	for _, r := range results {
		if r == SIGNED_TRUSTED || r == ORGANIZATIONAL_TRUSTED || r == ENDORSED_TRUSTED {
			trusted = max(trusted, r)
		} else {
			untrusted = max(untrusted, r)
		}
	}
	var out []VerificationResult
	if trusted != 0 {
		out = append(out, trusted)
	}
	if untrusted > trusted {
		out = append(out, untrusted)
	}
	return out
}
