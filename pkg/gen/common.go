package gen

import (
	"time"

	"github.com/adem-wg/adem-proto/pkg/args"
	"github.com/adem-wg/adem-proto/pkg/consts"
	"github.com/adem-wg/adem-proto/pkg/tokens"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type TokenGenerator interface {
	// Generate a signed token. First argument is the signed token, second
	// argument the bytes of the JWS in compact serialization.
	SignToken() (jwt.Token, []byte, error)
}

type EmblemConfig struct {
	sk       jwk.Key
	alg      *jwa.SignatureAlgorithm
	proto    jwt.Token
	lifetime int64
}

func MkEmblemCfg(sk jwk.Key, alg *jwa.SignatureAlgorithm, proto jwt.Token, lifetime int64) *EmblemConfig {
	return &EmblemConfig{sk: sk, alg: alg, proto: proto, lifetime: lifetime}
}

type EndorsementConfig struct {
	EmblemConfig
	endorse    jwk.Key
	endorseAlg *jwa.SignatureAlgorithm
}

func MkEndorsementCfg(sk jwk.Key, alg *jwa.SignatureAlgorithm, proto jwt.Token, endorse jwk.Key, endorseAlg *jwa.SignatureAlgorithm, lifetime int64) *EndorsementConfig {
	return &EndorsementConfig{
		EmblemConfig: *MkEmblemCfg(sk, alg, proto, lifetime),
		endorse:      endorse,
		endorseAlg:   endorseAlg,
	}
}

func prepToken(t jwt.Token, lifetime int64) error {
	iat := time.Now().Unix()
	if err := t.Set("iat", iat); err != nil {
		return err
	}
	if err := t.Set("nbf", iat); err != nil {
		return err
	}
	if err := t.Set("exp", iat+lifetime); err != nil {
		return err
	}
	return nil
}

func signWithHeaders(t jwt.Token, cty consts.CTY, alg *jwa.SignatureAlgorithm, signingKey jwk.Key) ([]byte, error) {
	headers := jws.NewHeaders()
	headers.Set("cty", string(cty))
	verifKey, err := signingKey.PublicKey()
	if err != nil {
		return nil, err
	} else if err := verifKey.Set("alg", alg.String()); err != nil {
		return nil, err
	} else if err := tokens.SetKID(verifKey, false); err != nil {
		return nil, err
	}

	if args.SetVerifyJWK {
		headers.Set("jwk", verifKey)
	} else {
		headers.Set("kid", verifKey.KeyID())
	}

	return jwt.Sign(t, jwt.WithKey(*alg, signingKey, jws.WithProtectedHeaders(headers)))
}
