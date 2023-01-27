package roots

import (
	"errors"
	"log"

	"github.com/adem-wg/adem-proto/pkg/tokens"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

var ErrNoLogConfig = errors.New("no log claim")

type VerificationResult struct {
	LogID string
	Ok    bool
}

func VerifyBindingCerts(iss string, key jwk.Key, logs []*tokens.LogConfig) []VerificationResult {
	verified := []VerificationResult{}
	for _, logConfig := range logs {
		result := VerificationResult{LogID: logConfig.Id}
		if logConfig.Ver != "v1" {
			log.Printf("log %s illegal version", logConfig.Id)
			result.Ok = false
		} else {
			err := VerifyBinding(logConfig.Id, logConfig.Hash.Raw, iss, key)
			if err != nil {
				log.Printf("log %s could not verify binding: %s", logConfig.Id, err)
			}
			result.Ok = err == nil
		}
		verified = append(verified, result)
	}
	return verified
}
