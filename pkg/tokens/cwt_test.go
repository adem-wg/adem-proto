package tokens_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/adem-wg/adem-proto/pkg/consts"
	"github.com/adem-wg/adem-proto/pkg/gen"
	"github.com/adem-wg/adem-proto/pkg/tokens"
	"github.com/adem-wg/adem-proto/pkg/vfy"
	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

func testKey(t *testing.T) *cose.Key {
	t.Helper()
	sk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := cose.NewKeyFromPrivate(sk)
	if err != nil {
		t.Fatal(err)
	}
	k.Algorithm = cose.AlgorithmES256
	return k
}
func proto(t *testing.T) *tokens.Claims {
	t.Helper()
	p, err := tokens.ParseClaims([]byte(`{"ver":1,"prp":1,"assets":["example.test"]}`))
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func TestCWTSignVerify(t *testing.T) {
	key := testKey(t)
	_, raw, err := gen.SignEmblem(key, cose.AlgorithmES256, proto(t), 3600)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(raw[:3]) != "d83dd2" {
		t.Fatalf("missing CWT/Sign1 tags: %x", raw[:3])
	}
	verified, err := vfy.VerifierFor(raw, key).Verify()
	if err != nil {
		t.Fatal(err)
	}
	if verified.IsEndorsement {
		t.Fatal("wrong type")
	}
	msg, err := tokens.DecodeMessage(raw)
	if err != nil {
		t.Fatal(err)
	}
	var claims map[any]any
	if err := cbor.Unmarshal(msg.Payload, &claims); err != nil {
		t.Fatal(err)
	}
	if claims["ver"] != uint64(1) || claims[uint64(6)] == nil || claims["iat"] != nil {
		t.Fatalf("incorrect CWT claims: %#v", claims)
	}
	carrier, err := tokens.EncodePublicCOSEKey(key)
	if err != nil {
		t.Fatal(err)
	}
	extracted, err := tokens.DecodePublicCOSEKey(carrier)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vfy.VerifierFor(raw, extracted).Verify(); err != nil {
		t.Fatal(err)
	}
	if _, err := vfy.VerifierFor(raw, testKey(t)).Verify(); err == nil {
		t.Fatal("accepted wrong key")
	}
	raw[len(raw)-1] ^= 1
	if _, err := vfy.VerifierFor(raw, key).Verify(); err == nil {
		t.Fatal("accepted tampered signature")
	}
}

func TestCWTRejectsMalformed(t *testing.T) {
	key := testKey(t)
	_, valid, err := gen.SignEmblem(key, cose.AlgorithmES256, proto(t), 3600)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(*cose.Sign1Message){
		"unprotected":     func(m *cose.Sign1Message) { m.Headers.Unprotected["x"] = true },
		"wrong typ":       func(m *cose.Sign1Message) { m.Headers.Protected[int64(16)] = "adem-emb" },
		"wrong kid":       func(m *cose.Sign1Message) { m.Headers.Protected[cose.HeaderLabelKeyID] = make([]byte, 32) },
		"text kid":        func(m *cose.Sign1Message) { m.Headers.Protected[cose.HeaderLabelKeyID] = "abc" },
		"missing payload": func(m *cose.Sign1Message) { m.Payload = nil },
		"missing nbf": func(m *cose.Sign1Message) {
			var c map[any]any
			cbor.Unmarshal(m.Payload, &c)
			delete(c, uint64(5))
			m.Payload, _ = tokens.CBOR.Marshal(c)
		},
		"text version": func(m *cose.Sign1Message) {
			var c map[any]any
			cbor.Unmarshal(m.Payload, &c)
			c["ver"] = "v1"
			m.Payload, _ = tokens.CBOR.Marshal(c)
		},
		"registered claim": func(m *cose.Sign1Message) {
			var c map[any]any
			cbor.Unmarshal(m.Payload, &c)
			c[uint64(3)] = "audience"
			m.Payload, _ = tokens.CBOR.Marshal(c)
		},
		"null purpose": func(m *cose.Sign1Message) {
			var c map[any]any
			cbor.Unmarshal(m.Payload, &c)
			c["prp"] = nil
			m.Payload, _ = tokens.CBOR.Marshal(c)
		},
		"expired": func(m *cose.Sign1Message) {
			var c map[any]any
			cbor.Unmarshal(m.Payload, &c)
			c[uint64(4)] = time.Now().Add(-time.Hour).Unix()
			m.Payload, _ = tokens.CBOR.Marshal(c)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			m, _ := tokens.DecodeMessage(valid)
			// Re-sign modifications, so malformed claims fail independently of signatures.
			m.Headers.RawProtected = nil
			m.Headers.RawUnprotected = nil
			mutate(m)
			m.Signature = nil
			ck, _ := tokens.WithAlgorithm(key, key.Algorithm)
			signer, _ := ck.Signer()
			if err := m.Sign(rand.Reader, nil, signer); err != nil {
				return
			}
			inner, err := m.MarshalCBOR()
			if err != nil {
				return
			}
			raw, err := tokens.CBOR.Marshal(cbor.RawTag{Number: 61, Content: inner})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := vfy.VerifierFor(raw, key).Verify(); err == nil {
				t.Fatal("accepted malformed CWT")
			}
		})
	}
	for name, raw := range map[string][]byte{"no CWT tag": valid[2:], "trailing": append(append([]byte(nil), valid...), 0), "JWT": []byte("a.b.c")} {
		t.Run(name, func(t *testing.T) {
			if _, err := tokens.DecodeMessage(raw); err == nil {
				t.Fatal("accepted malformed envelope")
			}
		})
	}
}

func TestCOSEThumbprintIndependentEncoding(t *testing.T) {
	key := testKey(t)
	public, err := key.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	pk := public.(*ecdsa.PublicKey)
	// A deterministic EC2 map with exactly kty, crv, x and y (RFC 9679).
	expected := []byte{0xa4, 0x01, 0x02, 0x20, 0x01, 0x21, 0x58, 0x20}
	expected = append(expected, pk.X.FillBytes(make([]byte, 32))...)
	expected = append(expected, 0x22, 0x58, 0x20)
	expected = append(expected, pk.Y.FillBytes(make([]byte, 32))...)
	digest := sha256.Sum256(expected)
	kid, err := tokens.CalcKID(key)
	if err != nil {
		t.Fatal(err)
	}
	if kid != tokens.KIDText(digest[:]) {
		t.Fatalf("incorrect thumbprint %s", kid)
	}
	key.ID = []byte("attacker-controlled")
	actual, err := tokens.GetKID(key)
	if err != nil || actual != kid {
		t.Fatal("trusted supplied kid")
	}
}

func TestTextFinalLine(t *testing.T) {
	key := testKey(t)
	_, raw, err := gen.SignEmblem(key, cose.AlgorithmES256, proto(t), 3600)
	if err != nil {
		t.Fatal(err)
	}
	records, err := tokens.ReadText(strings.NewReader(tokens.Text(raw)))
	if err != nil || len(records) != 1 {
		t.Fatalf("last line lost: %v", err)
	}
}

func TestEndorsementCWT(t *testing.T) {
	key, child := testKey(t), testKey(t)
	p, err := tokens.ParseClaims([]byte(`{"ver":1,"end":false,"prp":31}`))
	if err != nil {
		t.Fatal(err)
	}
	_, raw, err := gen.SignEndorsement(key, cose.AlgorithmES256, p, child, cose.AlgorithmES256, 3600)
	if err != nil {
		t.Fatal(err)
	}
	v, err := vfy.VerifierFor(raw, key).Verify()
	if err != nil {
		t.Fatal(err)
	}
	if !v.IsEndorsement {
		t.Fatal("not an endorsement")
	}
	m, _ := tokens.DecodeMessage(raw)
	if m.Headers.Protected[int64(16)] != consts.ADEMType {
		t.Fatal("wrong typ")
	}
	var c map[any]any
	cbor.Unmarshal(m.Payload, &c)
	if b, ok := c["key"].([]byte); !ok || len(b) != 32 {
		t.Fatal("key is not bstr")
	}
}

func TestProtectedLogEncoding(t *testing.T) {
	key, child := testKey(t), testKey(t)
	p, err := tokens.ParseClaims([]byte(`{"ver":1,"end":true,"iss":"https://example.test","prp":31}`))
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 32)
	hash := make([]byte, 32)
	hash[0] = 42
	p.Log = tokens.Log{&tokens.LogConfig{Id: base64.StdEncoding.EncodeToString(id), Hash: &tokens.LeafHash{Raw: hash, B64: base64.StdEncoding.EncodeToString(hash)}}}
	_, raw, err := gen.SignEndorsement(key, cose.AlgorithmES256, p, child, cose.AlgorithmES256, 3600)
	if err != nil {
		t.Fatal(err)
	}
	m, err := tokens.DecodeMessage(raw)
	if err != nil {
		t.Fatal(err)
	}
	var claims map[any]any
	cbor.Unmarshal(m.Payload, &claims)
	if _, ok := claims["log"]; ok {
		t.Fatal("log was encoded as a claim")
	}
	logs, ok := m.Headers.Protected["log"].([]any)
	if !ok || len(logs) != 1 {
		t.Fatal("log header missing")
	}
	entry := logs[0].(map[any]any)
	if b, ok := entry["hash"].([]byte); !ok || len(b) != 32 || b[0] != 42 {
		t.Fatal("hash must be bstr")
	}
	if _, err := vfy.VerifierFor(raw, key).Verify(); err != nil {
		t.Fatal(err)
	}
}

func TestSignatureAlgorithms(t *testing.T) {
	for _, tc := range []struct {
		curve elliptic.Curve
		alg   cose.Algorithm
	}{{elliptic.P256(), cose.AlgorithmES256}, {elliptic.P384(), cose.AlgorithmES384}, {elliptic.P521(), cose.AlgorithmES512}} {
		t.Run(tc.alg.String(), func(t *testing.T) {
			sk, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			key, err := cose.NewKeyFromPrivate(sk)
			if err != nil {
				t.Fatal(err)
			}
			key.Algorithm = tc.alg
			_, raw, err := gen.SignEmblem(key, tc.alg, proto(t), 3600)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := vfy.VerifierFor(raw, key).Verify(); err != nil {
				t.Fatal(err)
			}
		})
	}
	_, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := cose.NewKeyFromPrivate(sk)
	if err != nil {
		t.Fatal(err)
	}
	key.Algorithm = cose.AlgorithmEdDSA
	_, raw, err := gen.SignEmblem(key, cose.AlgorithmEdDSA, proto(t), 3600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vfy.VerifierFor(raw, key).Verify(); err != nil {
		t.Fatal(err)
	}
}

func TestOptionalTypeAndIssuedAt(t *testing.T) {
	key, child := testKey(t), testKey(t)
	for _, endorsement := range []bool{false, true} {
		for _, typ := range []string{consts.ADEMType, ""} {
			p := proto(t)
			if endorsement {
				var err error
				p, err = tokens.ParseClaims([]byte(`{"ver":1,"end":false,"prp":31}`))
				if err != nil {
					t.Fatal(err)
				}
				kid, _ := tokens.CalcKID(child)
				p.CWTClaims["key"] = keyIDBytes(t, kid)
			}
			p.CWTClaims[cose.CWTClaimNotBefore] = time.Now().Add(-time.Minute).Unix()
			p.CWTClaims[cose.CWTClaimExpirationTime] = time.Now().Add(time.Hour).Unix()
			payload, logs, err := tokens.EncodeClaims(p, endorsement)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := tokens.SignMessage(payload, typ, key, logs)
			if err != nil {
				t.Fatal(err)
			}
			verified, err := vfy.VerifierFor(raw, key).Verify()
			if err != nil {
				t.Fatal(err)
			}
			if verified.IsEndorsement != endorsement {
				t.Fatal("incorrect kind without distinct typ")
			}
			if verified.Token.CWTClaims[cose.CWTClaimIssuedAt] != nil {
				t.Fatal("iat was not optional")
			}
		}
	}
}

func TestRejectAmbiguousKindAndUnknownGeneratedClaims(t *testing.T) {
	key := testKey(t)
	p := proto(t)
	p.CWTClaims[cose.CWTClaimNotBefore] = time.Now().Add(-time.Minute).Unix()
	p.CWTClaims[cose.CWTClaimExpirationTime] = time.Now().Add(time.Hour).Unix()
	payload, _, err := tokens.EncodeClaims(p, false)
	if err != nil {
		t.Fatal(err)
	}
	var claims map[any]any
	cbor.Unmarshal(payload, &claims)
	claims["key"] = make([]byte, 32)
	claims["end"] = false
	payload, _ = tokens.CBOR.Marshal(claims)
	raw, err := tokens.SignMessage(payload, "", key, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vfy.VerifierFor(raw, key).Verify(); err == nil {
		t.Fatal("ambiguous token accepted")
	}
	p.CWTClaims["extension"] = true
	if _, _, err := gen.SignEmblem(key, cose.AlgorithmES256, p, 3600); err == nil {
		t.Fatal("generated unsupported claim")
	}
}

func TestBarePublicKeyAndIgnoredKID(t *testing.T) {
	key := testKey(t)
	raw, err := tokens.EncodePublicCOSEKey(key)
	if err != nil {
		t.Fatal(err)
	}
	var params map[int]any
	if err := cbor.Unmarshal(raw, &params); err != nil {
		t.Fatal(err)
	}
	if _, exists := params[2]; exists {
		t.Fatal("emitted kid")
	}
	if _, exists := params[-4]; exists {
		t.Fatal("emitted private key")
	}
	expected, _ := tokens.CalcKID(key)
	params[2] = []byte("incorrect supplied kid")
	raw, _ = tokens.CBOR.Marshal(params)
	decoded, err := tokens.DecodePublicCOSEKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	actual, _ := tokens.CalcKID(decoded)
	if actual != expected {
		t.Fatal("supplied kid was trusted")
	}
	text := strings.ToLower(tokens.Text(raw))
	spaced := text[:12] + " \t" + text[12:]
	parsed, err := tokens.ParseText(spaced)
	if err != nil || string(parsed) != string(raw) {
		t.Fatalf("hex whitespace/case: %v", err)
	}
	if _, err := tokens.DecodePublicCOSEKey(append(raw, 0)); err == nil {
		t.Fatal("accepted trailing data")
	}
	delete(params, 3)
	raw, _ = tokens.CBOR.Marshal(params)
	if _, err := tokens.DecodePublicCOSEKey(raw); err == nil {
		t.Fatal("accepted missing alg")
	}
}

func TestPurposeBitmapWireTypeAndRange(t *testing.T) {
	key := testKey(t)
	for _, endorsement := range []bool{false, true} {
		p := proto(t)
		if endorsement {
			p = tokens.NewClaims()
			p.CWTClaims["ver"] = uint64(1)
			p.CWTClaims["end"] = false
			kid, err := tokens.CalcKID(key)
			if err != nil {
				t.Fatal(err)
			}
			p.CWTClaims["key"] = keyIDBytes(t, kid)
		}
		p.CWTClaims[cose.CWTClaimNotBefore] = time.Now().Add(-time.Minute).Unix()
		p.CWTClaims[cose.CWTClaimExpirationTime] = time.Now().Add(time.Hour).Unix()
		p.CWTClaims["prp"] = uint64(31)
		payload, _, err := tokens.EncodeClaims(p, endorsement)
		if err != nil {
			t.Fatal(err)
		}
		var base map[any]any
		if err := cbor.Unmarshal(payload, &base); err != nil {
			t.Fatal(err)
		}
		if base["prp"] != uint64(31) || base["emb"] != nil {
			t.Fatalf("wrong purpose encoding: %#v", base)
		}
		for _, value := range []any{nil, uint64(0), uint64(1), uint64(3), uint64(31), uint64(32), int64(-1), 1.5, 1.0, "1", []any{"redcr-protective"}} {
			base["prp"] = value
			payload, err := tokens.CBOR.Marshal(base)
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = tokens.DecodeClaims(&cose.Sign1Message{Payload: payload})
			n, numeric := value.(uint64)
			want := numeric && n >= 1 && n <= 31
			if (err == nil) != want {
				t.Fatalf("endorsement=%v purpose=%#v: %v", endorsement, value, err)
			}
		}
		delete(base, "prp")
		payload, _ = tokens.CBOR.Marshal(base)
		if _, _, err := tokens.DecodeClaims(&cose.Sign1Message{Payload: payload}); err == nil {
			t.Fatal("missing purpose accepted")
		}
		p.CWTClaims["emb"] = tokens.EmblemConstraints{}
		if _, _, err := tokens.EncodeClaims(p, endorsement); err == nil {
			t.Fatal("generated obsolete emb")
		}
	}
}

func keyIDBytes(t *testing.T, kid string) []byte {
	t.Helper()
	raw, err := tokens.KIDBytes(kid)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
