package roots

import (
	"crypto/x509"
	"errors"
	"math"
	"net/http"

	"filippo.io/sunlight"
	"github.com/adem-wg/adem-proto/pkg/tokens"
	ctclient "github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
)

var ErrMissingV1URL = errors.New("missing CT v1 URL")
var ErrMissingStaticURL = errors.New("missing Static CT monitoring URL")

// TODO: Change user agent string
const staticCTUserAgent = "adem-proto (+https://github.com/adem-wg/adem-proto)"

type InclusionVerifier interface {
	URL() string
	VerifyInclusion(logConfig *tokens.LogConfig) ([]string, error)
}

type v1InclusionVerifier struct {
	client *ctclient.LogClient
}

func (v *v1InclusionVerifier) URL() string {
	return v.client.BaseURI()
}

func (v *v1InclusionVerifier) VerifyInclusion(logConfig *tokens.LogConfig) ([]string, error) {
	return verifyV1Inclusion(v.client, logConfig.Hash.Raw)
}

type staticInclusionVerifier struct {
	client        *sunlight.Client
	monitoringURL string
}

func (v *staticInclusionVerifier) URL() string {
	return v.monitoringURL
}

func (v *staticInclusionVerifier) VerifyInclusion(logConfig *tokens.LogConfig) ([]string, error) {
	if *logConfig.Index > math.MaxInt64 {
		return nil, errors.New("log index exceeds supported tree size")
	}
	return verifyStaticInclusion(v.client, int64(*logConfig.Index))
}

func GetInclusionVerifier(logConfig *tokens.LogConfig) (InclusionVerifier, error) {
	if logConfig == nil {
		return nil, ErrNoLogConfig
	}

	if err := logConfig.Validate(); err != nil {
		return nil, err
	}
	if logConfig.Hash != nil {
		if logInfo, err := GetV1Log(logConfig.Id); err != nil {
			return nil, err
		} else if logInfo.URL == "" {
			return nil, ErrMissingV1URL
		} else if client, err := ctclient.New(logInfo.URL, http.DefaultClient, jsonclient.Options{PublicKeyDER: logInfo.KeyDER}); err != nil {
			return nil, err
		} else {
			return &v1InclusionVerifier{client: client}, nil
		}
	} else {
		if logInfo, err := GetStaticLog(logConfig.Id); err != nil {
			return nil, err
		} else if logInfo.MonitoringURL == "" {
			return nil, ErrMissingStaticURL
		} else if key, err := x509.ParsePKIXPublicKey(logInfo.KeyDER); err != nil {
			return nil, err
		} else if client, err := sunlight.NewClient(&sunlight.ClientConfig{
			MonitoringPrefix: logInfo.MonitoringURL,
			PublicKey:        key,
			UserAgent:        staticCTUserAgent,
		}); err != nil {
			return nil, err
		} else {
			return &staticInclusionVerifier{client: client, monitoringURL: logInfo.MonitoringURL}, nil
		}
	}
}
