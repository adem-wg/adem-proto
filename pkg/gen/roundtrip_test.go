package gen

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"slices"
	"testing"

	"github.com/adem-wg/adem-proto/pkg/tokens"
	"github.com/adem-wg/adem-proto/pkg/vfy"
	"github.com/veraison/go-cose"
)

const testLifetime = 60

func newTestKey(t *testing.T) *cose.Key {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	secretKey, err := cose.NewKeyFromPrivate(privateKey)
	if err != nil {
		t.Fatalf("converting private key to COSE: %v", err)
	}
	secretKey.Algorithm = cose.AlgorithmES256
	return secretKey
}

func publicKey(t *testing.T, key *cose.Key) *cose.Key {
	t.Helper()

	publicMaterial, err := key.PublicKey()
	if err != nil {
		t.Fatalf("extracting public key: %v", err)
	}
	publicKey, err := cose.NewKeyFromPublic(publicMaterial)
	if err != nil {
		t.Fatalf("converting public key to COSE: %v", err)
	}
	publicKey.Algorithm = key.Algorithm
	return publicKey
}

func thumbprint(t *testing.T, key *cose.Key) string {
	t.Helper()

	thumbprint, err := tokens.COSEThumbprintB32(publicKey(t, key))
	if err != nil {
		t.Fatalf("computing key thumbprint: %v", err)
	}
	return thumbprint
}

func marshalPublicKey(t *testing.T, key *cose.Key) []byte {
	t.Helper()

	raw, err := publicKey(t, key).MarshalCBOR()
	if err != nil {
		t.Fatalf("marshalling public key: %v", err)
	}
	return raw
}

func newEmblemClaims() *tokens.Claims {
	return &tokens.Claims{
		Ver:    1,
		Prp:    tokens.RedCrProtective,
		Assets: []string{"example.com"},
	}
}

func newEndorsementClaims(end bool) *tokens.Claims {
	return &tokens.Claims{
		Ver: 1,
		Prp: tokens.RedCrProtective,
		End: &end,
	}
}

func signEmblem(t *testing.T, key *cose.Key) []byte {
	t.Helper()

	message, err := SignEmblem(key, newEmblemClaims(), testLifetime)
	if err != nil {
		t.Fatalf("signing emblem: %v", err)
	}
	return marshalMessage(t, message)
}

func signEndorsement(t *testing.T, signingKey, endorsedKey *cose.Key, end bool) []byte {
	t.Helper()

	message, err := SignEndorsement(
		signingKey,
		newEndorsementClaims(end),
		endorsedKey,
		testLifetime,
	)
	if err != nil {
		t.Fatalf("signing endorsement: %v", err)
	}
	return marshalMessage(t, message)
}

func marshalMessage(t *testing.T, message *cose.Sign1Message) []byte {
	t.Helper()

	raw, err := message.MarshalCBOR()
	if err != nil {
		t.Fatalf("marshalling signed token: %v", err)
	}
	return raw
}

func trusted(t *testing.T, key *cose.Key) tokens.KeySet {
	t.Helper()

	publicKey := publicKey(t, key)
	return tokens.KeySet{thumbprint(t, key): publicKey}
}

func requireLevels(t *testing.T, result vfy.VerificationResults, want ...vfy.VerificationResult) {
	t.Helper()

	if !slices.Equal(result.Results, want) {
		t.Fatalf("verification levels = %v, want %v", result.Results, want)
	}
}

func requireTrustChangesResult(t *testing.T, rawTokens [][]byte, key *cose.Key) {
	t.Helper()

	requireLevels(t, vfy.VerifyTokens(rawTokens, nil), vfy.SIGNED)
	requireLevels(
		t,
		vfy.VerifyTokens(rawTokens, trusted(t, key)),
		vfy.SIGNED,
		vfy.SIGNED_TRUSTED,
	)
}

func TestSignAndVerifyEmblem(t *testing.T) {
	emblemKey := newTestKey(t)
	rawTokens := [][]byte{marshalPublicKey(t, emblemKey), signEmblem(t, emblemKey)}

	requireTrustChangesResult(t, rawTokens, emblemKey)
}

func TestSignAndVerifyEmblemWithSingleEndorsement(t *testing.T) {
	emblemKey := newTestKey(t)
	endorsementKey := newTestKey(t)
	rawTokens := [][]byte{
		marshalPublicKey(t, emblemKey),
		marshalPublicKey(t, endorsementKey),
		signEmblem(t, emblemKey),
		signEndorsement(t, endorsementKey, emblemKey, false),
	}

	requireTrustChangesResult(t, rawTokens, endorsementKey)
}

func TestSignAndVerifyEmblemWithMultipleEndorsements(t *testing.T) {
	emblemKey := newTestKey(t)
	intermediateKey := newTestKey(t)
	rootKey := newTestKey(t)
	rawTokens := [][]byte{
		marshalPublicKey(t, emblemKey),
		marshalPublicKey(t, intermediateKey),
		marshalPublicKey(t, rootKey),
		signEmblem(t, emblemKey),
		signEndorsement(t, intermediateKey, emblemKey, false),
		signEndorsement(t, rootKey, intermediateKey, true),
	}

	requireTrustChangesResult(t, rawTokens, rootKey)
}

func TestVerifyRejectsEndorsementsThatDoNotFormChain(t *testing.T) {
	emblemKey := newTestKey(t)
	intermediateKey := newTestKey(t)
	rootKey := newTestKey(t)
	unrelatedKey := newTestKey(t)
	rawTokens := [][]byte{
		marshalPublicKey(t, emblemKey),
		marshalPublicKey(t, intermediateKey),
		marshalPublicKey(t, rootKey),
		marshalPublicKey(t, unrelatedKey),
		signEmblem(t, emblemKey),
		signEndorsement(t, intermediateKey, emblemKey, false),
		signEndorsement(t, rootKey, unrelatedKey, true),
	}

	requireLevels(t, vfy.VerifyTokens(rawTokens, trusted(t, rootKey)), vfy.INVALID)
}

func TestVerifyRejectsEndorsementForWrongKey(t *testing.T) {
	emblemKey := newTestKey(t)
	endorsementKey := newTestKey(t)
	wrongKey := newTestKey(t)
	rawTokens := [][]byte{
		marshalPublicKey(t, emblemKey),
		marshalPublicKey(t, endorsementKey),
		marshalPublicKey(t, wrongKey),
		signEmblem(t, emblemKey),
		signEndorsement(t, endorsementKey, wrongKey, false),
	}

	requireLevels(t, vfy.VerifyTokens(rawTokens, trusted(t, endorsementKey)), vfy.INVALID)
}
