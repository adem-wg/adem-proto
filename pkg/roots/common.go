package roots

import (
	"errors"
	"log"

	"github.com/adem-wg/adem-proto/pkg/tokens"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

var ErrNoLogConfig = errors.New("no log claim")

type VerificationResult struct {
	LogURL string
	LogID  string
	Ok     bool
}

func VerifyBindingCerts(iss string, key jwk.Key, logs []*tokens.LogConfig) []VerificationResult {
	verified := []VerificationResult{}
	for _, logConfig := range logs {
		result := VerificationResult{LogID: logConfig.Id}
		if logConfig.Ver != "v1" {
			log.Printf("log %s illegal version", logConfig.Id)
			result.Ok = false
		} else if cl, err := GetLogClient(logConfig.Id); err != nil {
			log.Print("could not get log client")
			result.Ok = false
		} else {
			result.LogURL = cl.BaseURI()
			err := VerifyBinding(cl, logConfig.Hash.Raw, iss, key)
			if err != nil {
				log.Printf("not verify binding: %s", err)
			}
			result.Ok = err == nil
		}
		verified = append(verified, result)
	}
	return verified
}
