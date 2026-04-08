package roots

import (
	"crypto/x509"
	"errors"
	"net/http"

	"filippo.io/sunlight"
	"github.com/adem-wg/adem-proto/pkg/consts"
	"github.com/adem-wg/adem-proto/pkg/tokens"
	ctclient "github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
)

var ErrIllegalLogVersion = errors.New("illegal log version")
var ErrMissingLeafHash = errors.New("missing leaf hash")
var ErrMissingLeafIndex = errors.New("missing leaf index")
var ErrMissingV1URL = errors.New("missing CT v1 URL")
var ErrMissingStaticURL = errors.New("missing Static CT monitoring URL")

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
	return verifyStaticInclusion(v.client, *logConfig.Index)
}

func GetInclusionVerifier(logConfig *tokens.LogConfig) (InclusionVerifier, error) {
	if logConfig == nil {
		return nil, ErrNoLogConfig
	}

	logInfo, err := GetLog(logConfig.Id)
	if err != nil {
		return nil, err
	}

	switch logConfig.Ver {
	case consts.LogVersionV1:
		if logConfig.Hash == nil {
			return nil, ErrMissingLeafHash
		}

		logURL := logInfo.v1URL()
		if logURL == "" {
			return nil, ErrMissingV1URL
		}

		client, err := ctclient.New(logURL, http.DefaultClient, jsonclient.Options{PublicKeyDER: logInfo.KeyDER})
		if err != nil {
			return nil, err
		}
		return &v1InclusionVerifier{client: client}, nil
	case consts.LogVersionStatic:
		if logConfig.Index == nil {
			return nil, ErrMissingLeafIndex
		}

		monitoringURL := logInfo.staticMonitoringURL()
		if monitoringURL == "" {
			return nil, ErrMissingStaticURL
		}

		key, err := x509.ParsePKIXPublicKey(logInfo.KeyDER)
		if err != nil {
			return nil, err
		}

		client, err := sunlight.NewClient(&sunlight.ClientConfig{
			MonitoringPrefix: monitoringURL,
			PublicKey:        key,
			UserAgent:        staticCTUserAgent,
		})
		if err != nil {
			return nil, err
		}
		return &staticInclusionVerifier{client: client, monitoringURL: monitoringURL}, nil
	default:
		return nil, ErrIllegalLogVersion
	}
}
