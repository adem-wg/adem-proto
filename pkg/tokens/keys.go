package tokens

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/veraison/go-cose"
)

var ErrNoEndorsedKey = errors.New("no valid endorsed key present")
var ErrAlgMissing = errors.New("input key misses algorithm")
var ErrUnsupportedKey = errors.New("unsupported key")

func GetEndorsedKID(c *Claims) (string, error) {
	if kid, ok := c.CWTClaims["key"].([]byte); ok && len(kid) == 32 {
		return KIDText(kid), nil
	}
	return "", ErrNoEndorsedKey
}

func GetKID(key *cose.Key) (string, error) { return CalcKID(key) }
func CalcKID(key *cose.Key) (string, error) {
	digest, err := keyDigest(key)
	if err != nil {
		return "", err
	}
	return KIDText(digest), nil
}

// PublicCOSEKey returns fresh public material, retaining the explicit algorithm
// and discarding asserted key IDs and private parameters.
func PublicCOSEKey(key *cose.Key) (*cose.Key, error) {
	if key == nil {
		return nil, ErrUnsupportedKey
	}
	if key.Algorithm == cose.AlgorithmReserved {
		return nil, ErrAlgMissing
	}
	pk, err := key.PublicKey()
	if err != nil {
		return nil, err
	}
	public, err := cose.NewKeyFromPublic(pk)
	if err != nil {
		return nil, err
	}
	if public.Algorithm != key.Algorithm {
		return nil, errors.New("key and signature algorithm disagree")
	}
	public.Ops = append([]cose.KeyOp(nil), key.Ops...)
	return public, nil
}

// WithAlgorithm applies an explicit algorithm to a copy and checks compatibility.
func WithAlgorithm(key *cose.Key, alg cose.Algorithm) (*cose.Key, error) {
	if key == nil {
		return nil, ErrUnsupportedKey
	}
	copy := *key
	copy.Algorithm = alg
	if _, err := PublicCOSEKey(&copy); err != nil {
		return nil, err
	}
	return &copy, nil
}

// KeySet indexes COSE keys by computed thumbprints, never by asserted kid values.
type KeySet map[string]*cose.Key

func NewKeySet() KeySet   { return KeySet{} }
func (s KeySet) Len() int { return len(s) }
func (s KeySet) AddKey(key *cose.Key) error {
	kid, err := CalcKID(key)
	if err != nil {
		return err
	}
	if s == nil {
		return errors.New("nil key set")
	}
	s[kid] = key
	return nil
}
func (s KeySet) LookupKeyID(kid string) (*cose.Key, bool) { k, ok := s[kid]; return k, ok }

func NormalizeKeys(keys KeySet) (KeySet, error) {
	normalized := NewKeySet()
	for _, key := range keys {
		public, err := PublicCOSEKey(key)
		if err != nil {
			return nil, err
		}
		if err := normalized.AddKey(public); err != nil {
			return nil, err
		}
	}
	return normalized, nil
}

func EncodePublicKey(key *cose.Key) (string, error) {
	public, err := PublicCOSEKey(key)
	if err != nil {
		return "", err
	}
	raw, err := public.PublicKey()
	if err != nil {
		return "", err
	}
	encoded, err := x509.MarshalPKIXPublicKey(raw)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(encoded), nil
}

func ParseAlgorithm(name string) (cose.Algorithm, bool) {
	switch name {
	case "ES256":
		return cose.AlgorithmES256, true
	case "ES384":
		return cose.AlgorithmES384, true
	case "ES512":
		return cose.AlgorithmES512, true
	case "EdDSA":
		return cose.AlgorithmEdDSA, true
	default:
		return cose.AlgorithmReserved, false
	}
}

func SetAlgorithms(keys KeySet, alg cose.Algorithm) (KeySet, error) {
	result := NewKeySet()
	for _, key := range keys {
		key, err := WithAlgorithm(key, alg)
		if err != nil {
			return nil, fmt.Errorf("public key algorithm: %w", err)
		}
		if err := result.AddKey(key); err != nil {
			return nil, err
		}
	}
	return result, nil
}
