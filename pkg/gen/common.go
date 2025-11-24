package gen

import (
	"time"

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
	setJwk   bool
}

func MkEmblemCfg(sk jwk.Key, alg *jwa.SignatureAlgorithm, proto jwt.Token, lifetime int64, setJwk bool) *EmblemConfig {
	return &EmblemConfig{sk: sk, alg: alg, proto: proto, lifetime: lifetime, setJwk: setJwk}
}

type EndorsementConfig struct {
	EmblemConfig
	endorse    jwk.Key
	endorseAlg *jwa.SignatureAlgorithm
	signKid    bool
}

func MkEndorsementCfg(sk jwk.Key, alg *jwa.SignatureAlgorithm, setJwk bool, proto jwt.Token, endorse jwk.Key, endorseAlg *jwa.SignatureAlgorithm, lifetime int64, signKid bool) *EndorsementConfig {
	return &EndorsementConfig{
		EmblemConfig: *MkEmblemCfg(sk, alg, proto, lifetime, setJwk),
		endorse:      endorse,
		endorseAlg:   endorseAlg,
		signKid:      signKid,
	}
}

func prepToken(t jwt.Token, lifetime int64) error {
	iat := time.Now().Unix()
	if err := t.Set("iat", iat); err != nil {
		return err
	}

	// Set nbf to iat if not already present
	nbf := iat
	if _, ok := t.Get("nbf"); ok {
		nbf = t.NotBefore().Unix()
	} else if err := t.Set("nbf", iat); err != nil {
		return err
	}

	// Only set lifetime if not already present
	if _, ok := t.Get("exp"); !ok {
		if err := t.Set("exp", nbf+lifetime); err != nil {
			return err
		}
	}
	return nil
}

func signWithHeaders(t jwt.Token, cty consts.CTY, alg *jwa.SignatureAlgorithm, signingKey jwk.Key, setJwk bool) ([]byte, error) {
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

	if setJwk {
		headers.Set("jwk", verifKey)
	} else {
		headers.Set("kid", verifKey.KeyID())
	}

	return jwt.Sign(t, jwt.WithKey(*alg, signingKey, jws.WithProtectedHeaders(headers)))
}
