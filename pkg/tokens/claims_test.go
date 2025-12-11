package tokens

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/adem-wg/adem-proto/pkg/consts"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

func TestPurposeMaskJSONRoundtrip(t *testing.T) {
	var pm PurposeMask = Protective | Indicative

	bs, err := json.Marshal(&pm)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var decoded PurposeMask
	if err := json.Unmarshal(bs, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if decoded != pm {
		t.Fatalf("expected %b after roundtrip, got %b", pm, decoded)
	}
}

func TestPurposeMaskInvalid(t *testing.T) {
	var pm PurposeMask
	if err := json.Unmarshal([]byte(`["`+consts.Protective+`","unknown"]`), &pm); err == nil {
		t.Fatalf("expected unknown constant to error")
	}
}

func TestChannelMaskJSONRoundtrip(t *testing.T) {
	var cm ChannelMask = DNS | TLS | UDP

	bs, err := json.Marshal(&cm)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var decoded ChannelMask
	if err := json.Unmarshal(bs, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if decoded != cm {
		t.Fatalf("expected %b after roundtrip, got %b", cm, decoded)
	}
}

func TestChannelMaskInvalid(t *testing.T) {
	var cm ChannelMask
	if err := json.Unmarshal([]byte(`["`+consts.DNS+`","unknown"]`), &cm); err == nil {
		t.Fatalf("expected unknown constant to error")
	}
}

func TestLeafHashJSON(t *testing.T) {
	var h LeafHash
	if err := json.Unmarshal([]byte(`"YWJj"`), &h); err != nil {
		t.Fatalf("expected unmarshal to succeed: %v", err)
	}
	if h.B64 != "YWJj" || string(h.Raw) != "abc" {
		t.Fatalf("unexpected leaf hash values: %+v", h)
	}
	if bs, err := json.Marshal(&h); err != nil || string(bs) != `"YWJj"` {
		t.Fatalf("unexpected marshal result %q (err=%v)", string(bs), err)
	}
}

func TestEmbeddedKeyUnmarshalKey(t *testing.T) {
	var ek EmbeddedKey
	if priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatalf("failed to generate key: %v", err)
	} else if key, err := jwk.Import(priv); err != nil {
		t.Fatalf("failed to wrap key: %v", err)
	} else if pk, err := key.PublicKey(); err != nil {
		t.Fatalf("cannot get public key: %v", err)
	} else if err := pk.Set("alg", jwa.ES256()); err != nil {
		t.Fatalf("set alg: %v", err)
	} else if expectedKid, err := SetKID(pk, true); err != nil {
		t.Fatalf("set kid: %v", err)
	} else if bs, err := json.Marshal(pk); err != nil {
		t.Fatalf("marshal key: %v", err)
	} else if err := json.Unmarshal(bs, &ek); err != nil {
		t.Fatalf("unmarshal embedded key: %v", err)
	} else if ek.Key == nil {
		t.Fatalf("expected parsed key to be present")
	} else if !jwk.Equal(pk, *ek.Key) {
		t.Fatalf("parsed key does not equal serialized key")
	} else if ek.Kid != expectedKid {
		t.Fatalf("unexpected kid %q, want %q", ek.Kid, expectedKid)
	}
}

func TestEmbeddedKeyUnmarshalKidOnly(t *testing.T) {
	var ek EmbeddedKey
	if err := json.Unmarshal([]byte(`"kid123"`), &ek); err != nil {
		t.Fatalf("unmarshal kid only: %v", err)
	} else if ek.Key != nil {
		t.Fatalf("expected no parsed key when value is bare kid")
	} else if ek.Kid != "kid123" {
		t.Fatalf("unexpected kid %q", ek.Kid)
	}
}

func TestValidateOI(t *testing.T) {
	if err := validateOI("https://example.com"); err != nil {
		t.Fatalf("expected valid OI, got %v", err)
	} else if err := validateOI("http://example.com"); err == nil {
		t.Fatalf("expected invalid scheme to fail validation")
	} else if err := validateOI("https://example.com/path"); err == nil {
		t.Fatalf("expected path to make OI invalid")
	}
}
