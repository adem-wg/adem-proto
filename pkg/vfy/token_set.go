package vfy

import (
	"errors"
	"fmt"

	"github.com/adem-wg/adem-proto/pkg/tokens"
	"github.com/veraison/go-cose"
)

type TokenVerifier struct {
	Verify func() (*ADEMToken, error)
}

type TokenSet struct {
	verified     map[string]bool
	dependencies map[string][]TokenVerifier
	keyMaterial  map[string]*cose.Key
	roots        []ADEMToken
	results      []ADEMToken
	errors       []error
}

func NewTokenSet(keyMaterial tokens.KeySet) TokenSet {
	var th TokenSet
	th.verified = make(map[string]bool)
	th.dependencies = make(map[string][]TokenVerifier)
	th.keyMaterial = keyMaterial
	th.roots = make([]ADEMToken, 0)
	th.results = make([]ADEMToken, 0)
	th.errors = make([]error, 0)
	return th
}

func (th *TokenSet) AddToken(rawToken []byte) error {
	msg := cose.NewSign1Message()
	if err := msg.UnmarshalCBOR(rawToken); err != nil {
		return err
	}

	var verificationKey *cose.Key
	var verificationKid string
	if headerKid, ok := msg.Headers.Protected[cose.HeaderLabelKeyID]; !ok {
		return ErrNoKeyFound
	} else if headerKidBs, ok := headerKid.([]byte); !ok {
		return ErrNoKeyFound
	} else {
		verificationKid = tokens.ThumbprintToString(headerKidBs)
		if kidKey, ok := th.keyMaterial[verificationKid]; !ok {
			return ErrNoKeyFound
		} else {
			verificationKey = kidKey
		}
	}

	verifier, isRoot := VerifierFor(msg, verificationKid, verificationKey)
	if isRoot {
		if t, err := verifier.Verify(); err != nil {
			return err
		} else {
			th.roots = append(th.roots, *t)
		}
	} else {
		th.dependencies[verificationKid] = append(th.dependencies[verificationKid], verifier)
	}
	return nil
}

func (th *TokenSet) Verify(trustedKeys tokens.KeySet) ([]ADEMToken, []error) {
	for _, r := range th.roots {
		if kid, ok := r.Token.GetEndorsedKID(); ok {
			th.results = append(th.results, r)
			th.setVerified(kid)
		} else {
			th.errors = append(th.errors, errors.New("endorsement without endorsed key"))
		}
	}

	for kid, _ := range trustedKeys {
		th.setVerified(kid)
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
			if endorsedKid, ok := t.Token.GetEndorsedKID(); ok {
				th.setVerified(endorsedKid)
			}
		}
	}
}
