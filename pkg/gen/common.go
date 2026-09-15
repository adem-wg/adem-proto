package gen

import (
	"errors"
	"math"
	"time"

	"github.com/adem-wg/adem-proto/pkg/consts"
	"github.com/adem-wg/adem-proto/pkg/tokens"
	"github.com/veraison/go-cose"
)

type TokenGenerator interface {
	// Generate a signed token. First argument is the signed token, second
	// argument the bytes of the signed CWT.
	SignToken() (*tokens.Claims, []byte, error)
}

type EmblemConfig struct {
	sk       *cose.Key
	alg      cose.Algorithm
	proto    *tokens.Claims
	lifetime int64
}

func MkEmblemCfg(sk *cose.Key, alg cose.Algorithm, proto *tokens.Claims, lifetime int64) *EmblemConfig {
	return &EmblemConfig{sk: sk, alg: alg, proto: proto, lifetime: lifetime}
}

type EndorsementConfig struct {
	EmblemConfig
	endorse    *cose.Key
	endorseAlg cose.Algorithm
}

func MkEndorsementCfg(sk *cose.Key, alg cose.Algorithm, proto *tokens.Claims, endorse *cose.Key, endorseAlg cose.Algorithm, lifetime int64) *EndorsementConfig {
	return &EndorsementConfig{
		EmblemConfig: *MkEmblemCfg(sk, alg, proto, lifetime),
		endorse:      endorse,
		endorseAlg:   endorseAlg,
	}
}

func prepToken(t *tokens.Claims, lifetime int64) error {
	if t == nil || t.CWTClaims == nil {
		return errors.New("missing claims prototype")
	}
	now := time.Now().Unix()
	t.CWTClaims[cose.CWTClaimIssuedAt] = now
	if _, ok := t.CWTClaims[cose.CWTClaimNotBefore]; !ok {
		t.CWTClaims[cose.CWTClaimNotBefore] = now
	}
	if _, ok := t.CWTClaims[cose.CWTClaimExpirationTime]; !ok {
		nbf, err := tokens.NumericDate(t.CWTClaims[cose.CWTClaimNotBefore])
		if err != nil {
			return err
		}
		if lifetime > 0 && nbf.Unix() > math.MaxInt64-lifetime || lifetime < 0 && nbf.Unix() < math.MinInt64-lifetime {
			return errors.New("token lifetime overflows NumericDate")
		}
		t.CWTClaims[cose.CWTClaimExpirationTime] = nbf.Unix() + lifetime
		if nbf.Nanosecond() != 0 {
			t.CWTClaims[cose.CWTClaimExpirationTime] = float64(nbf.Unix()+lifetime) + float64(nbf.Nanosecond())/1e9
		}
	}
	return nil
}

func signWithHeaders(t *tokens.Claims, endorsement bool, alg cose.Algorithm, signingKey *cose.Key) ([]byte, error) {
	signingKey, err := tokens.WithAlgorithm(signingKey, alg)
	if err != nil {
		return nil, err
	}
	payload, logs, err := tokens.EncodeClaims(t, endorsement)
	if err != nil {
		return nil, err
	}
	return tokens.SignMessage(payload, consts.ADEMType, signingKey, logs)
}
