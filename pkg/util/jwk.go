package util

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

func GetEndorsedKID(t jwt.Token) (string, error) {
	k, ok := t.Get("key")
	if !ok {
		return "", errors.New("no endorsed key present")
	}
	jwKey, err := jwk.ParseKey([]byte(k.(string)))
	if err != nil {
		return "", err
	}
	kid, err := GetKID(jwKey)
	if err != nil {
		return "", err
	}
	return kid, nil
}

func GetKID(key jwk.Key) (string, error) {
	if key.KeyID() != "" {
		return key.KeyID(), nil
	}

	// TODO: This misses the case where key = {...,"kid": ""}
	jsonKey, err := json.Marshal(key)
	if err != nil {
		return "", err
	}

	canonical, err := jsoncanonicalizer.Transform(jsonKey)
	if err != nil {
		return "", err
	}

	h := sha256.Sum256(canonical)
	return base64.StdEncoding.EncodeToString(h[:]), nil
}

func SetKID(key *jwk.Key) error {
	kid, err := GetKID(*key)
	if err != nil {
		return err
	}
	(*key).Set("kid", kid)
	return nil
}
