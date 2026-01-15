package vfy

import (
	"errors"
	"fmt"

	"github.com/adem-wg/adem-proto/pkg/roots"
	"github.com/adem-wg/adem-proto/pkg/tokens"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

type TokenVerifier struct {
	Verify func() (*ADEMToken, error)
}

type TokenSet struct {
	verified     map[string]bool
	dependencies map[string][]TokenVerifier
	roots        []ADEMToken
	results      []ADEMToken
	errors       []error
}

func NewTokenSet() TokenSet {
	var th TokenSet
	th.verified = make(map[string]bool)
	th.dependencies = make(map[string][]TokenVerifier)
	th.roots = make([]ADEMToken, 0)
	th.results = make([]ADEMToken, 0)
	th.errors = make([]error, 0)
	return th
}

func (th *TokenSet) AddToken(rawToken []byte) error {
	if msg, err := jws.Parse(rawToken); err != nil {
		return err
	} else if len(msg.Signatures()) != 1 {
		return ErrTokenNonCompact
	} else if headerKey, ok := msg.Signatures()[0].ProtectedHeaders().JWK(); headerKey == nil || !ok {
		return ErrNoKeyFound
	} else if verificationKid, err := tokens.SetKID(headerKey, true); err != nil {
		return err
	} else {
		verifier := VerifierFor(rawToken, headerKey)
		var logs tokens.Log
		if body, err := jwt.Parse(msg.Payload(), jwt.WithVerify(false)); err != nil {
			return err
		} else if err := body.Get("log", &logs); err != nil && !errors.Is(err, jwt.ClaimNotFoundError()) {
			return err
		} else if err == nil {
			if len(logs) == 0 {
				return ErrLogsEmpty
			} else if iss, ok := body.Issuer(); !ok {
				return ErrNoIss
			} else if t, err := verifier.Verify(); err != nil {
				return err
			} else {
				for _, r := range roots.VerifyBindingCerts(iss, headerKey, logs) {
					if !r.Ok {
						return ErrRootKeyUnbound
					}
				}
				th.roots = append(th.roots, *t)
			}
		} else {
			th.dependencies[verificationKid] = append(th.dependencies[verificationKid], verifier)
		}
		return nil
	}
}

func (th *TokenSet) Verify(trustedKeys jwk.Set) ([]ADEMToken, []error) {
	for _, r := range th.roots {
		if kid, err := tokens.GetEndorsedKID(r.Token); err == nil {
			th.results = append(th.results, r)
			th.setVerified(kid)
		} else {
			th.errors = append(th.errors, err)
		}
	}

	for i := range trustedKeys.Len() {
		if k, ok := trustedKeys.Key(i); !ok {
			th.errors = append(th.errors, fmt.Errorf("could not access trusted keys at index %s", i))
		} else if kid, err := tokens.SetKID(k, true); err != nil {
			th.errors = append(th.errors, err)
		} else {
			th.setVerified(kid)
		}
	}

	count := 0
	for _, deps := range th.dependencies {
		count += len(deps)
	}

	if count > 0 {
		th.errors = append(th.errors, fmt.Errorf("could not validate verification key for %d token(s)", count))
	}

	return th.results, th.errors
}

func (th *TokenSet) setVerified(kid string) {
	th.verified[kid] = true
	dependencies, okD := th.dependencies[kid]
	if !okD {
		return
	}

	// Reset dependencies before running the depending verifiers to prevent
	// infinite recursion
	th.dependencies[kid] = make([]TokenVerifier, 0)
	for _, v := range dependencies {
		if t, err := v.Verify(); err != nil {
			th.errors = append(th.errors, err)
		} else {
			th.results = append(th.results, *t)
			if endorsedKid, err := tokens.GetEndorsedKID(t.Token); err == nil {
				th.setVerified(endorsedKid)
			}
		}
	}
}
