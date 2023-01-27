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

type TokenConfig struct {
	Sk      jwk.Key
	Alg     *jwa.SignatureAlgorithm
	Proto   jwt.Token
	Endorse *jwk.Key
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
	} else if err := tokens.SetKID(verifKey); err != nil {
		return nil, err
	} else if err := verifKey.Set("alg", alg.String()); err != nil {
		return nil, err
	}

	if args.SetVerifyJWK {
		headers.Set("jwk", verifKey)
	} else {
		headers.Set("kid", verifKey.KeyID())
	}

	return jwt.Sign(t, jwt.WithKey(*alg, signingKey, jws.WithProtectedHeaders(headers)))
}
