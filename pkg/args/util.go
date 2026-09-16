package args

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/adem-wg/adem-proto/pkg/tokens"
	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

var ErrEmptyPath = errors.New("no path provided")
var ErrMultipleKeyFiles = errors.New("provide either a CBOR key file or a PEM key file, not both")

func ParseAlgorithm(value string) (cose.Algorithm, error) {
	switch strings.ToUpper(value) {
	case "ES256":
		return cose.AlgorithmES256, nil
	case "ES384":
		return cose.AlgorithmES384, nil
	case "ES512":
		return cose.AlgorithmES512, nil
	case "EDDSA":
		return cose.AlgorithmEdDSA, nil
	case "":
		return cose.AlgorithmReserved, errors.New("algorithm is required")
	default:
		if number, err := strconv.ParseInt(value, 10, 64); err != nil {
			return cose.AlgorithmReserved, fmt.Errorf("unknown COSE algorithm %q", value)
		} else {
			return cose.Algorithm(number), nil
		}
	}
}

func parsePEMKeys(raw []byte) ([]*cose.Key, error) {
	keys := make([]*cose.Key, 0)
	for len(bytes.TrimSpace(raw)) > 0 {
		block, rest := pem.Decode(raw)
		if block == nil {
			return nil, errors.New("could not decode PEM key")
		}
		raw = rest

		var key any
		var err error
		switch block.Type {
		case "EC PRIVATE KEY":
			key, err = x509.ParseECPrivateKey(block.Bytes)
		case "PRIVATE KEY":
			key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		case "PUBLIC KEY":
			key, err = x509.ParsePKIXPublicKey(block.Bytes)
		default:
			err = fmt.Errorf("unsupported PEM block %q", block.Type)
		}
		if err != nil {
			return nil, err
		}

		var coseKey *cose.Key
		switch key := key.(type) {
		case *ecdsa.PrivateKey:
			coseKey, err = cose.NewKeyFromPrivate(key)
		case *ecdsa.PublicKey:
			coseKey, err = cose.NewKeyFromPublic(key)
		default:
			coseKey, err = cose.NewKeyFromPublic(key)
		}
		if err != nil {
			return nil, err
		}
		keys = append(keys, coseKey)
	}
	return keys, nil
}

func LoadKeys(cborPath, pemPath string) ([]*cose.Key, error) {
	if cborPath != "" && pemPath != "" {
		return nil, ErrMultipleKeyFiles
	}
	if cborPath == "" && pemPath == "" {
		return nil, ErrEmptyPath
	}

	path := cborPath
	if path == "" {
		path = pemPath
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	if cborPath != "" {
		var keys []*cose.Key
		if err := cbor.Unmarshal(raw, &keys); err != nil {
			return nil, fmt.Errorf("could not decode CBOR key array: %w", err)
		}
		return keys, nil
	}

	return parsePEMKeys(raw)
}

func PublicKey(key *cose.Key) (*cose.Key, error) {
	publicMaterial, err := key.PublicKey()
	if err != nil {
		return nil, err
	}
	publicKey, err := cose.NewKeyFromPublic(publicMaterial)
	if err != nil {
		return nil, err
	}
	publicKey.Algorithm = key.Algorithm
	return publicKey, nil
}

func KeySet(keys []*cose.Key) (tokens.KeySet, error) {
	set := tokens.KeySet{}
	for _, key := range keys {
		publicKey, err := PublicKey(key)
		if err != nil {
			return nil, err
		}
		if err := tokens.AddKey(set, publicKey); err != nil {
			return nil, err
		}
	}
	return set, nil
}
