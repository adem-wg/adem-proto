package io

import (
	"time"

	"github.com/adem-wg/adem-proto/pkg/gen"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type EmblemRefresher struct {
	emblemCfg    *gen.EmblemConfig
	threshold    int64
	lastToken    jwt.Token
	lastTokenRaw []byte
	lastErr      error
}

// Returns an instance of [gen.TokenGenerator]. Generates an emblem according to
// the given [gen.EmblemConfig] but only every threshold many seconds. Calls to
// SignToken() will return the most recently signed token.
func MkRefresher(cfg *gen.EmblemConfig, threshold int64) *EmblemRefresher {
	return &EmblemRefresher{emblemCfg: cfg, threshold: threshold}
}

func (er *EmblemRefresher) SignToken() (jwt.Token, []byte, error) {
	if er.lastToken == nil || er.lastToken.Expiration().Unix() <= time.Now().Unix()+er.threshold {
		er.lastToken, er.lastTokenRaw, er.lastErr = er.emblemCfg.SignToken()
	}
	return er.lastToken, er.lastTokenRaw, er.lastErr
}
