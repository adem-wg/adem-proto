package tokens

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"errors"
	"strings"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

var ErrNoEndorsedKey = errors.New("no endorsed key present")

func GetEndorsedKID(t jwt.Token) (string, error) {
	if jwKey, ok := t.Get("key"); !ok {
		return "", ErrNoEndorsedKey
	} else if kid, err := GetKID(jwKey.(EmbeddedKey).Key); err != nil {
		return "", err
	} else {
		return kid, nil
	}
}

func GetKID(key jwk.Key) (string, error) {
	if key.KeyID() != "" {
		return key.KeyID(), nil
	}

	return CalcKID(key)
}

func CalcKID(key jwk.Key) (string, error) {
	if pk, err := key.PublicKey(); err != nil {
		return "", err
	} else if err := pk.Remove("kid"); err != nil {
		return "", err
	} else if jsonKey, err := json.Marshal(pk); err != nil {
		return "", err
	} else if canonical, err := jsoncanonicalizer.Transform(jsonKey); err != nil {
		return "", err
	} else {
		h := sha256.Sum256(canonical)
		b32 := base32.StdEncoding.EncodeToString(h[:])
		return strings.ToLower(strings.TrimRight(b32, "=")), nil
	}
}

func SetKID(key jwk.Key) error {
	if kid, err := GetKID(key); err != nil {
		return err
	} else {
		return key.Set("kid", kid)
	}
}
