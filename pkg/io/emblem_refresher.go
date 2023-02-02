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

func MkRefresher(cfg *gen.EmblemConfig, threshold int64) *EmblemRefresher {
	return &EmblemRefresher{emblemCfg: cfg, threshold: threshold}
}

func (er *EmblemRefresher) SignToken() (jwt.Token, []byte, error) {
	if er.lastToken == nil || er.lastToken.Expiration().Unix() <= time.Now().Unix()+int64(er.threshold) {
		er.lastToken, er.lastTokenRaw, er.lastErr = er.emblemCfg.SignToken()
	}
	return er.lastToken, er.lastTokenRaw, er.lastErr
}
