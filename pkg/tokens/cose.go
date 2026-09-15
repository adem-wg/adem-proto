package tokens

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"strings"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

var CBOR, _ = cbor.CoreDetEncOptions().EncMode()
var strictCBOR, _ = (cbor.DecOptions{DupMapKey: cbor.DupMapKeyEnforcedAPF, MaxNestedLevels: 16, MaxArrayElements: 4096, MaxMapPairs: 256}).DecMode()

func KIDText(digest []byte) string {
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(digest))
}

func KIDBytes(kid string) ([]byte, error) {
	b, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(kid))
	if err != nil || len(b) != 32 || KIDText(b) != kid {
		return nil, errors.New("invalid key identifier")
	}
	return b, nil
}

func keyDigest(key *cose.Key) ([]byte, error) {
	ck, err := PublicCOSEKey(key)
	if err != nil {
		return nil, err
	}
	// RFC 9679: only kty and the required public key parameters, excluding alg.
	ck.Algorithm = cose.AlgorithmReserved
	ck.Ops = nil
	encoded, err := ck.MarshalCBOR()
	if err != nil {
		return nil, err
	}
	var params map[int64]any
	if err := strictCBOR.Unmarshal(encoded, &params); err != nil {
		return nil, err
	}
	encoded, err = CBOR.Marshal(params)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(encoded)
	return digest[:], nil
}

// DecodeMessage requires both the CWT and COSE_Sign1 tags and a single data item.
func DecodeMessage(raw []byte) (*cose.Sign1Message, error) {
	var tag cbor.RawTag
	if err := strictCBOR.Unmarshal(raw, &tag); err != nil {
		return nil, err
	}
	if tag.Number != 61 {
		return nil, errors.New("missing CWT tag 61")
	}
	var inner cbor.RawTag
	if err := strictCBOR.Unmarshal(tag.Content, &inner); err != nil {
		return nil, err
	}
	if inner.Number != 18 {
		return nil, errors.New("missing COSE_Sign1 tag 18")
	}
	var fields []cbor.RawMessage
	if err := strictCBOR.Unmarshal(inner.Content, &fields); err != nil {
		return nil, err
	}
	if len(fields) != 4 {
		return nil, errors.New("COSE_Sign1 must contain four fields")
	}
	// Normalize only the outer array/tag; signed header and payload bytes remain exact.
	normalized, err := CBOR.Marshal(cbor.Tag{Number: 18, Content: fields})
	if err != nil {
		return nil, err
	}
	m := cose.NewSign1Message()
	if err := m.UnmarshalCBOR(normalized); err != nil {
		return nil, err
	}
	if m.Payload == nil || len(m.Headers.Unprotected) != 0 {
		return nil, errors.New("payload required and unprotected header must be empty")
	}
	if _, err := m.Headers.Protected.Algorithm(); err != nil {
		return nil, err
	}
	if kid, ok := m.Headers.Protected[cose.HeaderLabelKeyID].([]byte); !ok || len(kid) != 32 {
		return nil, errors.New("protected kid must be a 32-byte string")
	}
	critical, err := m.Headers.Protected.Critical()
	if err != nil {
		return nil, err
	}
	for _, label := range critical {
		switch label {
		case int64(1), int64(4), int64(16), "log":
		default:
			return nil, errors.New("unsupported critical header")
		}
	}
	return m, nil
}

func SignMessage(payload []byte, typ string, key *cose.Key, logs any) ([]byte, error) {
	_, err := PublicCOSEKey(key)
	ck := key
	if err != nil {
		return nil, err
	}
	kid, err := keyDigest(key)
	if err != nil {
		return nil, err
	}
	m := cose.NewSign1Message()
	m.Payload = payload
	m.Headers.Protected[cose.HeaderLabelAlgorithm] = ck.Algorithm
	m.Headers.Protected[cose.HeaderLabelKeyID] = kid
	if typ != "" {
		m.Headers.Protected[int64(16)] = typ
	}
	if logs != nil {
		m.Headers.Protected["log"] = logs
	}
	signer, err := ck.Signer()
	if err != nil {
		return nil, err
	}
	if err := m.Sign(rand.Reader, nil, signer); err != nil {
		return nil, err
	}
	signed, err := m.MarshalCBOR()
	if err != nil {
		return nil, err
	}
	return CBOR.Marshal(cbor.RawTag{Number: 61, Content: signed})
}

func VerifyMessage(m *cose.Sign1Message, key *cose.Key) error {
	ck, err := PublicCOSEKey(key)
	if err != nil {
		return err
	}
	kid, err := keyDigest(key)
	if err != nil {
		return err
	}
	headerKid, ok := m.Headers.Protected[cose.HeaderLabelKeyID].([]byte)
	if !ok || string(headerKid) != string(kid) {
		return errors.New("verification key does not match protected kid")
	}
	alg, err := m.Headers.Protected.Algorithm()
	if err != nil || alg != ck.Algorithm {
		return errors.New("verification key algorithm does not match protected alg")
	}
	verifier, err := ck.Verifier()
	if err != nil {
		return err
	}
	return m.Verify(nil, verifier)
}

// EncodePublicCOSEKey emits public material without an asserted kid.
func EncodePublicCOSEKey(public *cose.Key) ([]byte, error) {
	ck, err := PublicCOSEKey(public)
	if err != nil {
		return nil, err
	}
	return ck.MarshalCBOR()
}

// DecodePublicCOSEKey ignores any supplied kid and derives the identifier from
// the public key. This never establishes trust in discovered key material.
func DecodePublicCOSEKey(encoded []byte) (*cose.Key, error) {
	if len(encoded) == 0 || encoded[0]>>5 != 5 {
		return nil, errors.New("COSE_Key must be a CBOR map")
	}
	var params map[int]cbor.RawMessage
	if err := strictCBOR.Unmarshal(encoded, &params); err != nil {
		return nil, err
	}
	// Ignore the optional assertion before importing the key.
	delete(params, 2)
	encoded, err := CBOR.Marshal(params)
	if err != nil {
		return nil, err
	}
	if _, ok := params[-4]; ok {
		return nil, errors.New("public COSE_Key contains private material")
	}
	if _, ok := params[3]; !ok {
		return nil, ErrAlgMissing
	}
	var ck cose.Key
	if err := ck.UnmarshalCBOR(encoded); err != nil {
		return nil, err
	}
	return PublicCOSEKey(&ck)
}
