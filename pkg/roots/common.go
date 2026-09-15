package roots

import (
	"errors"
	"fmt"
	"log"
	"net/url"

	"github.com/adem-wg/adem-proto/pkg/tokens"
	"github.com/adem-wg/adem-proto/pkg/util"
	"github.com/veraison/go-cose"
)

var ErrIssNoHostName = errors.New("issuer has no hostname")
var ErrCertNotForIss = errors.New("certificate is not valid for issuer OI")
var ErrCertNotForKey = errors.New("certificate is not valid for key")
var ErrNoLogConfig = errors.New("no log claim")

type CTQueryResult struct {
	LogURL   string
	LogID    string
	Ok       bool
	subjects []string
}

// Verify that the given key was correctly committed to the Certificate
// Transparency infrastructure for the given issuer.
func VerifyBindingCerts(iss string, key *cose.Key, logs []*tokens.LogConfig) []CTQueryResult {
	verified := VerifyInclusionConfig(logs)
	for i := range verified {
		verified[i].Ok = verified[i].Ok && VerifyBinding(verified[i], iss, key) == nil
	}
	return verified
}

// Verify that the rootKey is correctly bound to the issuer OI in the
// certificate's subjects referenced by the CT query.
func VerifyBinding(q CTQueryResult, issuer string, rootKey *cose.Key) error {
	kid, err := tokens.CalcKID(rootKey)
	if err != nil {
		log.Print("could not calculate KID")
		return err
	}
	issuerUrl, err := url.Parse(issuer)
	if err != nil {
		log.Print("could not parse issuer")
		return err
	} else if issuerUrl.Hostname() == "" {
		return ErrIssNoHostName
	}

	if !util.Contains(q.subjects, "adem-configuration."+issuerUrl.Hostname()) {
		return ErrCertNotForIss
	} else if !util.Contains(q.subjects, fmt.Sprintf("%s.adem-configuration.%s", kid, issuerUrl.Hostname())) {
		return ErrCertNotForKey
	}
	return nil
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
			if subjs, err := verifier.VerifyInclusion(logConfig); err != nil {
				log.Printf("could not verify binding: %s", err)
				result.Ok = false
			} else {
				result.Ok = true
				result.subjects = subjs
			}
		}
		results = append(results, result)
	}
	return results
}
