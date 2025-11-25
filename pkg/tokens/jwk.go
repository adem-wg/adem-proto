package tokens

import (
	"crypto"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"strings"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

var ErrNoEndorsedKey = errors.New("no endorsed key present")
var ErrAlgMissing = errors.New("input key misses algorithm")

// Get the KID of a key endorsed in an emblem. If the endorsed key has no KID,
// it will be calculated.
func GetEndorsedKID(t jwt.Token) (string, error) {
	var jwKey EmbeddedKey
	if err := t.Get("key", &jwKey); err != nil {
		if errors.Is(err, jwt.ClaimNotFoundError()) {
			return "", ErrNoEndorsedKey
		} else {
			return "", err
		}
	} else if kid, err := GetKID(jwKey.Key); err != nil {
		return "", err
	} else {
		return kid, nil
	}
}

// Get a key's KID. If it has no KID, it will be calculated.
func GetKID(key jwk.Key) (string, error) {
	if kid, ok := key.KeyID(); ok {
		return kid, nil
	}

	return CalcKID(key)
}

// Calculate a key's KID by hashing it using a canonical JSON representation and
// SHA256. This function will drop any private-key parameters.
func CalcKID(key jwk.Key) (string, error) {
	if pk, err := key.PublicKey(); err != nil {
		return "", err
	} else if alg, ok := key.Algorithm(); !ok || alg.String() == "" {
		return "", ErrAlgMissing
	} else if err := pk.Set("alg", alg); err != nil {
		return "", err
	} else if err := pk.Remove("kid"); err != nil {
		return "", err
	} else if digest, err := pk.Thumbprint(crypto.SHA256); err != nil {
		return "", err
	} else {
		b32 := base32.StdEncoding.EncodeToString(digest)
		return strings.ToLower(strings.TrimRight(b32, "=")), nil
	}
}

// Set a key's KID if not already present.
func SetKID(key jwk.Key, force bool) (string, error) {
	var kid string
	var err error
	if force {
		kid, err = CalcKID(key)
	} else {
		kid, err = GetKID(key)
	}

	if err != nil {
		return kid, err
	} else {
		return kid, key.Set("kid", kid)
	}
}

// Calculate and set the KID of every key in the given set. Will override old
// KIDs.
func SetKIDs(set jwk.Set, alg jwa.SignatureAlgorithm) (jwk.Set, error) {
	withKIDs := jwk.NewSet()
	for i := range set.Len() {
		if k, ok := set.Key(i); !ok {
			panic("index out of bounds")
		} else if pk, err := k.PublicKey(); err != nil {
			return nil, err
		} else {
			if _, ok := pk.Algorithm(); !ok {
				if err := pk.Set("alg", alg); err != nil {
					return nil, err
				}
			}
			if _, err := SetKID(pk, true); err != nil {
				return nil, err
			}
			withKIDs.AddKey(pk)
		}
	}
	return withKIDs, nil
}

func EncodePublicKey(key jwk.Key) (string, error) {
	var raw any
	if pk, err := key.PublicKey(); err != nil {
		return "", err
	} else if err := jwk.Export(pk, &raw); err != nil {
		return "", err
	} else if bs, err := x509.MarshalPKIXPublicKey(raw); err != nil {
		return "", err
	} else {
		return base64.StdEncoding.EncodeToString(bs), nil
	}
}
