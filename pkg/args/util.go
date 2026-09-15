package args

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/adem-wg/adem-proto/pkg/tokens"
	"github.com/veraison/go-cose"
)

var ErrEmptyPath = errors.New("no path provided")

// LoadKeys accepts PEM public keys, SEC1/PKCS8 private keys, and certificates.
func LoadKeys(path string) (tokens.KeySet, error) {
	if path == "" {
		return nil, ErrEmptyPath
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParsePEMKeys(data)
}

func ParsePEMKeys(data []byte) (tokens.KeySet, error) {
	keys := tokens.NewKeySet()
	for len(bytes.TrimSpace(data)) > 0 {
		data = bytes.TrimSpace(data)
		if !bytes.HasPrefix(data, []byte("-----BEGIN ")) {
			return nil, errors.New("expected PEM key; JSON/JWK input is not supported")
		}
		block, rest := pem.Decode(data)
		if block == nil {
			return nil, errors.New("invalid PEM block")
		}
		data = rest
		var raw any
		var err error
		private := false
		switch block.Type {
		case "EC PRIVATE KEY":
			raw, err = x509.ParseECPrivateKey(block.Bytes)
			private = true
		case "PRIVATE KEY":
			raw, err = x509.ParsePKCS8PrivateKey(block.Bytes)
			private = true
		case "PUBLIC KEY":
			raw, err = x509.ParsePKIXPublicKey(block.Bytes)
		case "CERTIFICATE":
			var cert *x509.Certificate
			cert, err = x509.ParseCertificate(block.Bytes)
			if err == nil {
				raw = cert.PublicKey
			}
		case "EC PARAMETERS":
			continue // OpenSSL can prepend curve parameters.
		default:
			return nil, fmt.Errorf("unsupported PEM block %q", block.Type)
		}
		if err != nil {
			return nil, err
		}
		var key *cose.Key
		if private {
			key, err = cose.NewKeyFromPrivate(raw)
		} else {
			key, err = cose.NewKeyFromPublic(raw)
		}
		if err != nil {
			return nil, err
		}
		if err := keys.AddKey(key); err != nil {
			return nil, err
		}
	}
	if len(keys) == 0 {
		return nil, errors.New("no PEM keys found")
	}
	return keys, nil
}
