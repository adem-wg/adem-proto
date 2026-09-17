package tokens

import (
	"bytes"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"strings"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

func ParseKey(raw []byte) (*cose.Key, error) {
	k := cose.Key{}
	if err := (&k).UnmarshalCBOR(bytes.Clone(raw)); err != nil {
		return nil, err
	} else {
		return &k, nil
	}
}

type ecKey struct {
	Kty int    `cbor:"1,keyasint"`
	Crv int    `cbor:"-1,keyasint"`
	X   []byte `cbor:"-2,keyasint"`
	Y   []byte `cbor:"-3,keyasint"`
}

func COSEThumbprint(key *cose.Key) ([]byte, error) {
	if encoder, err := cbor.CoreDetEncOptions().EncMode(); err != nil {
		return nil, err
	} else if key.Type == cose.KeyTypeEC2 {
		crv, x, y, _ := key.EC2()
		var k = ecKey{Kty: int(cose.KeyTypeEC2), Crv: int(crv), X: x, Y: y}
		if bs, err := encoder.Marshal(k); err != nil {
			return nil, err
		} else {
			digest := sha256.Sum256(bs)
			return digest[:], nil
		}
	} else {
		return nil, errors.New("unsupported key type")
	}
}

func COSEThumbprintB32(key *cose.Key) (string, error) {
	if thumbprint, err := COSEThumbprint(key); err != nil {
		return "", err
	} else {
		return ThumbprintToString(thumbprint), nil
	}
}

func ThumbprintToString(thumbprint []byte) string {
	encoded := base32.StdEncoding.EncodeToString(thumbprint)
	return strings.ToLower(strings.TrimRight(encoded, "="))
}

type KeySet = map[string]*cose.Key

func AddKey(s KeySet, k *cose.Key) error {
	publicMaterial, err := k.PublicKey()
	if err != nil {
		return err
	}
	publicKey, err := cose.NewKeyFromPublic(publicMaterial)
	if err != nil {
		return err
	}
	publicKey.Algorithm = k.Algorithm
	kid, err := COSEThumbprintB32(publicKey)
	if err != nil {
		return err
	}
	s[kid] = publicKey
	return nil
}

func AddSet(keys KeySet, source KeySet) {
	if source == nil {
		return
	}

	for k, v := range source {
		keys[k] = v
	}
}
