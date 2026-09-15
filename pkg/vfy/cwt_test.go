package vfy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"reflect"
	"testing"

	"github.com/adem-wg/adem-proto/pkg/gen"
	"github.com/adem-wg/adem-proto/pkg/tokens"
	"github.com/veraison/go-cose"
)

func keyForTest(t *testing.T) *cose.Key {
	t.Helper()
	sk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := cose.NewKeyFromPrivate(sk)
	if err != nil {
		t.Fatal(err)
	}
	key.Algorithm = cose.AlgorithmES256
	return key
}
func claimsForTest(t *testing.T, s string) *tokens.Claims {
	t.Helper()
	c, err := tokens.ParseClaims([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func TestSuppliedKeysAndDiscardedFailures(t *testing.T) {
	signer, authority := keyForTest(t), keyForTest(t)
	_, emblem, err := gen.SignEmblem(signer, cose.AlgorithmES256, claimsForTest(t, `{"ver":1,"assets":["example.test"],"prp":1}`), 3600)
	if err != nil {
		t.Fatal(err)
	}
	_, endorsement, err := gen.SignEndorsement(authority, cose.AlgorithmES256, claimsForTest(t, `{"ver":1,"end":false,"prp":31}`), signer, cose.AlgorithmES256, 3600)
	if err != nil {
		t.Fatal(err)
	}
	signerCWT, err := tokens.EncodePublicCOSEKey(signer)
	if err != nil {
		t.Fatal(err)
	}
	authorityCWT, err := tokens.EncodePublicCOSEKey(authority)
	if err != nil {
		t.Fatal(err)
	}
	// Keys and tokens intentionally arrive out of order.
	input := [][]byte{endorsement, signerCWT, emblem, authorityCWT}
	trusted := tokens.NewKeySet()
	trusted.AddKey(authority)
	r := VerifyTokensWithCT(input, trusted, false)
	if len(r.results) != 1 || r.results[0] != SIGNED_TRUSTED {
		t.Fatalf("trusted chain: %v", r.results)
	}
	r = VerifyTokensWithCT(input, tokens.NewKeySet(), false)
	if len(r.results) != 1 || r.results[0] != SIGNED {
		t.Fatalf("key material acquired trust: %v", r.results)
	}
	// A forged kid on an unrelated key must not grant trust.
	unrelated := keyForTest(t)
	kid, _ := tokens.GetKID(authority)
	unrelated.ID = []byte(kid)
	forged := tokens.NewKeySet()
	forged.AddKey(unrelated)

	r = VerifyTokensWithCT(input, forged, false)
	if len(r.results) != 1 || r.results[0] != SIGNED {
		t.Fatalf("forged kid acquired trust: %v", r.results)
	}
	endorsement[len(endorsement)-1] ^= 1
	r = VerifyTokensWithCT(input, trusted, false)
	if len(r.results) != 1 || r.results[0] != SIGNED {
		t.Fatalf("invalid endorsement was not discarded: %v", r.results)
	}
}

func TestInvalidExternalEndorsementIgnored(t *testing.T) {
	signer, external := keyForTest(t), keyForTest(t)
	_, emblem, err := gen.SignEmblem(signer, cose.AlgorithmES256, claimsForTest(t, `{"ver":1,"assets":["example.test"],"prp":1}`), 3600)
	if err != nil {
		t.Fatal(err)
	}
	_, endorsement, err := gen.SignEndorsement(external, cose.AlgorithmES256, claimsForTest(t, `{"ver":1,"end":true,"iss":"https://other.test","prp":31}`), signer, cose.AlgorithmES256, 3600)
	if err != nil {
		t.Fatal(err)
	}
	carrier, err := tokens.EncodePublicCOSEKey(external)
	if err != nil {
		t.Fatal(err)
	}
	endorsement[len(endorsement)-1] ^= 1
	trusted := tokens.NewKeySet()
	trusted.AddKey(signer)
	result := VerifyTokensWithCT([][]byte{emblem, endorsement, carrier}, trusted, false)
	if len(result.results) != 1 || result.results[0] != SIGNED_TRUSTED {
		t.Fatalf("external failure invalidated signed emblem: %v", result.results)
	}
}

func TestPurposeMismatchDeniesEmblem(t *testing.T) {
	signer, authority := keyForTest(t), keyForTest(t)
	_, emblem, err := gen.SignEmblem(signer, cose.AlgorithmES256, claimsForTest(t, `{"ver":1,"assets":["example.test"],"prp":1}`), 3600)
	if err != nil {
		t.Fatal(err)
	}
	_, endorsement, err := gen.SignEndorsement(authority, cose.AlgorithmES256, claimsForTest(t, `{"ver":1,"end":false,"prp":2}`), signer, cose.AlgorithmES256, 3600)
	if err != nil {
		t.Fatal(err)
	}
	keys := tokens.NewKeySet()
	keys.AddKey(signer)
	keys.AddKey(authority)
	if result := VerifyTokensWithCT([][]byte{emblem, endorsement}, keys, false); result.Valid() {
		t.Fatal("purpose mismatch accepted")
	}
}

func TestEmblemSelectionAfterFiltering(t *testing.T) {
	key := keyForTest(t)
	keys := tokens.NewKeySet()
	keys.AddKey(key)
	sign := func() []byte {
		_, raw, err := gen.SignEmblem(key, cose.AlgorithmES256, claimsForTest(t, `{"ver":1,"prp":1,"assets":["example.test"]}`), 3600)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	first, second := sign(), sign()
	if result := VerifyTokensWithCT([][]byte{first, second}, keys, false); result.Valid() {
		t.Fatal("multiple emblems accepted")
	}
	second[len(second)-1] ^= 1
	if result := VerifyTokensWithCT([][]byte{first, second}, keys, false); !result.Valid() {
		t.Fatal("invalid second emblem not discarded")
	}
	if result := VerifyTokensWithCT([][]byte{second}, keys, false); result.Valid() {
		t.Fatal("zero valid emblems accepted")
	}
}

func TestOrganizationalAndAuthorityValidation(t *testing.T) {
	emblem := ADEMToken{VerificationKid: "t6irmh2dim7etjw6nw3ibv47makz6lskzelsminbfbdefakyiqfq", Token: claimsForTest(t, `{"iss":"https://issuer.test","prp":1}`)}
	internal := ADEMToken{IsEndorsement: true, VerificationKid: "jajustitpylddo5dahk2zk3opo32u5gocgc5ivswl32r243wo6za", Token: claimsForTest(t, `{"iss":"https://issuer.test","sub":"https://issuer.test","key":"t6irmh2dim7etjw6nw3ibv47makz6lskzelsminbfbdefakyiqfq","end":false,"prp":1}`), commitment: func() bool { return true }}
	internal.Token.Log = tokens.Log{} // commitment callback stands in for CT I/O
	external := ADEMToken{IsEndorsement: true, VerificationKid: "r53p2ua3w2hpoh2oe5v4fdzjxtqqaoymfsozi6g6qg237qgn4huq", Token: claimsForTest(t, `{"iss":"https://authority.test","sub":"https://issuer.test","key":"jajustitpylddo5dahk2zk3opo32u5gocgc5ivswl32r243wo6za","end":true,"prp":1}`), commitment: func() bool { return true }}
	external.Token.Log = tokens.Log{}
	keys := tokens.NewKeySet()
	levels, root := verifySignedOrganizational(emblem, []ADEMToken{external, internal}, keys)
	if len(levels) != 2 || levels[0] != SIGNED || levels[1] != ORGANIZATIONAL || root == nil {
		t.Fatalf("organizational: %v", levels)
	}
	levels, issuers := verifyEndorsed(emblem, *root, []ADEMToken{internal, external, external}, keys)
	if len(levels) != 1 || levels[0] != ENDORSED || len(issuers) != 1 || issuers[0] != "https://authority.test" {
		t.Fatalf("endorsed: %v %v", levels, issuers)
	}
	// Internal helpers receive normalized key sets; use the fixture identifiers
	// here to exercise trust at each level independently of CT I/O.
	for _, tc := range []struct {
		kid  string
		want []VerificationResult
	}{
		{"t6irmh2dim7etjw6nw3ibv47makz6lskzelsminbfbdefakyiqfq", []VerificationResult{SIGNED_TRUSTED, ENDORSED}},
		{"jajustitpylddo5dahk2zk3opo32u5gocgc5ivswl32r243wo6za", []VerificationResult{ORGANIZATIONAL_TRUSTED, ENDORSED}},
		{"r53p2ua3w2hpoh2oe5v4fdzjxtqqaoymfsozi6g6qg237qgn4huq", []VerificationResult{ENDORSED_TRUSTED}},
	} {
		trusted := tokens.NewKeySet()
		key := keyForTest(t)
		trusted[tc.kid] = key

		internalLevels, trustedRoot := verifySignedOrganizational(emblem, []ADEMToken{internal}, trusted)
		externalLevels, _ := verifyEndorsed(emblem, *trustedRoot, []ADEMToken{external}, trusted)
		got := strongest(append(internalLevels, externalLevels...))
		if !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("trusted %s: got %v, want %v", tc.kid, got, tc.want)
		}
	}
	external.commitment = func() bool { return false }
	levels, issuers = verifyEndorsed(emblem, *root, []ADEMToken{external}, keys)
	if len(levels) != 0 || len(issuers) != 0 {
		t.Fatal("unbound authority accepted")
	}
	internal.commitment = func() bool { return false }
	levels, _ = verifySignedOrganizational(emblem, []ADEMToken{internal}, keys)
	if len(levels) != 1 || levels[0] != INVALID {
		t.Fatal("unbound issuer accepted")
	}
}

func TestInternalChainRequirements(t *testing.T) {
	emblem := ADEMToken{VerificationKid: "t6irmh2dim7etjw6nw3ibv47makz6lskzelsminbfbdefakyiqfq", Token: claimsForTest(t, `{"prp":1}`)}
	first := ADEMToken{IsEndorsement: true, VerificationKid: "useiv5henqjjy2k64mtxlkgcgpyrhsboptkon7j4xmp5uvsz6nva", Token: claimsForTest(t, `{"key":"t6irmh2dim7etjw6nw3ibv47makz6lskzelsminbfbdefakyiqfq","end":false,"prp":1}`)}
	root := ADEMToken{IsEndorsement: true, VerificationKid: "jajustitpylddo5dahk2zk3opo32u5gocgc5ivswl32r243wo6za", Token: claimsForTest(t, `{"key":"useiv5henqjjy2k64mtxlkgcgpyrhsboptkon7j4xmp5uvsz6nva","end":true,"prp":3}`)}
	keys := tokens.NewKeySet()
	check := func(want VerificationResult, endorsements ...ADEMToken) {
		t.Helper()
		results, _ := verifySignedOrganizational(emblem, endorsements, keys)
		if len(results) != 1 || results[0] != want {
			t.Fatalf("got %v want %v", results, want)
		}
	}
	check(SIGNED)
	check(SIGNED, root, first)
	check(INVALID, first, first)
	check(INVALID, root)
	root.Token.CWTClaims["end"] = false
	check(INVALID, first, root)
	root.Token.CWTClaims["end"] = true
	root.VerificationKid = "t6irmh2dim7etjw6nw3ibv47makz6lskzelsminbfbdefakyiqfq"
	check(INVALID, first, root)
}
