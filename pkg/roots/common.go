package roots

import (
	"errors"
	"log"

	"github.com/adem-wg/adem-proto/pkg/tokens"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

var ErrNoLogConfig = errors.New("no log claim")

type VerificationResult struct {
	LogID  string
	Result bool
}

func VerifyBindingCerts(iss string, key jwk.Key, logs []*tokens.LogConfig) []VerificationResult {
	verified := []VerificationResult{}
	for _, logConfig := range logs {
		if logConfig.Ver != "v1" {
			log.Printf("log %s illegal version", logConfig.Id)
		} else {
			err := VerifyBinding(logConfig.Id, logConfig.Hash.Raw, iss, key)
			if err != nil {
				log.Printf("log %s could not verify binding: %s", logConfig.Id, err)
			}
			verified = append(verified, VerificationResult{LogID: logConfig.Id, Result: err == nil})
		}
	}
	return verified
}
