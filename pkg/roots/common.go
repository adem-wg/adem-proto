package roots

import (
	"errors"
	"log"

	"github.com/adem-wg/adem-proto/pkg/tokens"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

var ErrNoLogConfig = errors.New("no log claim")

type CTQueryResult struct {
	LogURL   string
	LogID    string
	Ok       bool
	subjects []string
}

// Verify that the given key was correctly committed to the Certificate
// Transparency infrastructure for the given issuer.
func VerifyBindingCerts(iss string, key jwk.Key, logs []*tokens.LogConfig) []CTQueryResult {
	verified := VerifyInclusionConfig(logs)
	for i := range verified {
		verified[i].Ok = VerifyBinding(verified[i], iss, key) == nil
	}
	return verified
}

// Verify that the hashes in the log configs are included in the respective CT
// logs.
func VerifyInclusionConfig(logs []*tokens.LogConfig) []CTQueryResult {
	results := []CTQueryResult{}
	for _, logConfig := range logs {
		result := CTQueryResult{}
		if logConfig == nil {
			log.Print("nil log config")
			result.Ok = false
		} else if verifier, err := GetInclusionVerifier(logConfig); err != nil {
			result.LogID = logConfig.Id
			log.Printf("could not get log client: %s", err)
			result.Ok = false
		} else {
			result.LogID = logConfig.Id
			result.LogURL = verifier.URL()
			subjs, err := verifier.VerifyInclusion(logConfig)
			if err != nil {
				log.Printf("could not verify binding: %s", err)
			}
			result.Ok = err == nil
			result.subjects = subjs
		}
		results = append(results, result)
	}
	return results
}
