package vfy

import (
	"errors"
	"log"

	"github.com/adem-wg/adem-proto/pkg/roots"
	"github.com/adem-wg/adem-proto/pkg/tokens"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

type TokenVerifier struct {
	Verify func(key jwk.Key) (*ADEMToken, error)
}

type TokenSet struct {
	keys         map[string]jwk.Key
	verified     map[string]bool
	dependencies map[string][]TokenVerifier
	results      []ADEMToken
	errors       []error
}

func NewTokenSet(untrustedKeys jwk.Set) TokenSet {
	var th TokenSet
	if untrustedKeys != nil {
		th.keys = make(map[string]jwk.Key, untrustedKeys.Len())
		for i := 0; i < untrustedKeys.Len(); i++ {
			k, ok := untrustedKeys.Key(i)
			if !ok {
				panic("index out of bounds")
			}
			if kid, err := tokens.GetKID(k); err == nil {
				th.keys[kid] = k
			}
		}
	} else {
		th.keys = make(map[string]jwk.Key)
	}

	th.verified = make(map[string]bool)
	th.dependencies = make(map[string][]TokenVerifier)
	th.results = make([]ADEMToken, 0)
	th.errors = make([]error, 0)
	return th
}

func (th *TokenSet) AddToken(rawToken []byte) error {
	if msg, err := jws.Parse(rawToken); err != nil {
		return err
	} else if len(msg.Signatures()) != 1 {
		return ErrTokenNonCompact
	} else {
		verifier := VerifierFor(rawToken)

		var verificationKey jwk.Key
		var verificationKid string

		headers := msg.Signatures()[0].ProtectedHeaders()
		headerKey, _ := headers.JWK()
		if headerKey != nil {
			verificationKey = headerKey
			if kid, err := tokens.SetKID(verificationKey, true); err != nil {
				return err
			} else {
				verificationKid = kid
			}
		} else if headerKid, hasHeaderKeyID := headers.KeyID(); hasHeaderKeyID {
			verificationKid = headerKid
		} else {
			return ErrNoKeyFound
		}

		var logs tokens.Log
		if body, err := jwt.Parse(msg.Payload(), jwt.WithVerify(false)); err != nil {
			return err
		} else if err := body.Get("log", &logs); err != nil && !errors.Is(err, jwt.ClaimNotFoundError()) {
			return err
		} else if err == nil {
			if verificationKey == nil {
				if mappedKey, haveKey := th.keys[verificationKid]; haveKey {
					verificationKey = mappedKey
				} else {
					return ErrNoKeyFound
				}
			}

			if len(logs) == 0 {
				return ErrLogsEmpty
			} else if iss, ok := body.Issuer(); !ok {
				return ErrNoIss
			} else {
				for _, r := range roots.VerifyBindingCerts(iss, verificationKey, logs) {
					if !r.Ok {
						return ErrRootKeyUnbound
					}
				}
				th.runVerifier(verifier, verificationKey)
			}
		} else {
			if k := th.get(verificationKid); k != nil {
				th.runVerifier(verifier, k)
			} else {
				th.dependencies[verificationKid] = append(th.dependencies[verificationKid], verifier)
			}
		}
	}

	return nil
}

func (th *TokenSet) runVerifier(tv TokenVerifier, key jwk.Key) {
	if t, err := tv.Verify(key); err != nil {
		th.errors = append(th.errors, err)
	} else {
		if endorsedKid, err := tokens.GetEndorsedKID(t.Token); err != nil && !errors.Is(err, jwt.ClaimNotFoundError()) {
			th.errors = append(th.errors, err)
			return
		} else if err == nil {
			th.setVerified(endorsedKid)
		}
		th.results = append(th.results, *t)
	}
}

func (th *TokenSet) setVerified(kid string) {
	_, ok := th.keys[kid]
	if !ok {
		return
	}

	th.verified[kid] = true
	th.resolve(kid)
}

// Store a verified key and notify listeners waiting for that key.
func (th *TokenSet) put(k jwk.Key) {
	if kid, err := tokens.SetKID(k, true); err != nil {
		th.errors = append(th.errors, err)
	} else {
		if _, ok := th.keys[kid]; !ok {
			th.keys[kid] = k
		}
		th.setVerified(kid)
	}
}

func (th *TokenSet) resolve(kid string) {
	k, okK := th.keys[kid]
	v, okV := th.verified[kid]
	dependencies, okD := th.dependencies[kid]
	if !okK || !v || !okV || !okD {
		return
	}

	// Reset dependencies before running the depending verifiers to prevent
	// infinite recursion
	th.dependencies[kid] = make([]TokenVerifier, 0)
	for _, v := range dependencies {
		th.runVerifier(v, k)
	}
}

func (th *TokenSet) get(kid string) jwk.Key {
	if k, ok := th.keys[kid]; !ok {
		return nil
	} else if vfd, ok := th.verified[kid]; !vfd || !ok {
		return nil
	} else {
		return k
	}
}

func (th *TokenSet) logErrors() {
	count := 0
	for _, deps := range th.dependencies {
		count += len(deps)
	}

	if count > 0 {
		log.Printf("could not validate verification key for %d token(s)", count)
	}

	if len(th.errors) > 0 {
		log.Printf("encountered the following errors during token verification...")
		for i, err := range th.errors {
			log.Printf("error %d: %s", i, err)
		}
	}
}
