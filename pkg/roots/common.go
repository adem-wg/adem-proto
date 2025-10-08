package roots

import (
	"errors"
	"log"

	"github.com/adem-wg/adem-proto/pkg/tokens"
	"github.com/lestrrat-go/jwx/v2/jwk"
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
	for _, queryResult := range verified {
		queryResult.Ok = VerifyBinding(queryResult, iss, key) == nil
	}
	return verified
}

// Verify that the hashes in the log configs are included in the respective CT
// logs.
func VerifyInclusionConfig(logs []*tokens.LogConfig) []CTQueryResult {
	results := []CTQueryResult{}
	for _, logConfig := range logs {
		result := CTQueryResult{LogID: logConfig.Id}
		if logConfig.Ver != "v1" {
			log.Printf("log %s illegal version", logConfig.Id)
			result.Ok = false
		} else if cl, err := GetLogClient(logConfig.Id); err != nil {
			log.Print("could not get log client")
			result.Ok = false
		} else {
			result.LogURL = cl.BaseURI()
			subjs, err := VerifyInclusion(cl, logConfig.Hash.Raw)
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
