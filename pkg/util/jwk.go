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

func GetEndorsedJWK(t jwt.Token) (jwk.Key, error) {
	k, ok := t.Get("key")
	if !ok {
		return nil, errors.New("no endorsed key present")
	}
	bs, err := json.Marshal(k)
	if err != nil {
		return nil, err
	}
	jwKey, err := jwk.ParseKey(bs)
	if err != nil {
		return nil, err
	}
	return jwKey, nil
}

func GetEndorsedKID(t jwt.Token) (string, error) {
	jwKey, err := GetEndorsedJWK(t)
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

func SetKID(key jwk.Key) error {
	kid, err := GetKID(key)
	if err != nil {
		return err
	}
	key.Set("kid", kid)
	return nil
}
