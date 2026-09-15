package tokens

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/adem-wg/adem-proto/pkg/consts"
)

func TestPurposeMaskJSONRoundtrip(t *testing.T) {
	var pm PurposeMask = Protective | Indicative

	if bs, err := json.Marshal(&pm); err != nil {
		t.Fatalf("marshal failed: %v", err)
	} else {
		var decoded PurposeMask
		if err := json.Unmarshal(bs, &decoded); err != nil {
			t.Fatalf("unmarshal failed: %v", err)
		} else if decoded != pm {
			t.Fatalf("expected %b after roundtrip, got %b", pm, decoded)
		}
	}
}

func TestPurposeMaskInvalid(t *testing.T) {
	var pm PurposeMask
	if err := json.Unmarshal([]byte(`["`+consts.Protective+`","unknown"]`), &pm); err == nil {
		t.Fatalf("expected unknown constant to error")
	}
}

func TestChannelMaskJSONRoundtrip(t *testing.T) {
	var cm ChannelMask = DNS

	if bs, err := json.Marshal(&cm); err != nil {
		t.Fatalf("marshal failed: %v", err)
	} else {
		var decoded ChannelMask
		if err := json.Unmarshal(bs, &decoded); err != nil {
			t.Fatalf("unmarshal failed: %v", err)
		} else if decoded != cm {
			t.Fatalf("expected %b after roundtrip, got %b", cm, decoded)
		}
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

func TestStaticLogConfigJSON(t *testing.T) {
	var cfg LogConfig
	if err := json.Unmarshal([]byte(`{"id":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","index":42}`), &cfg); err != nil {
		t.Fatalf("expected unmarshal to succeed: %v", err)
	}
	if cfg.Id != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" {
		t.Fatalf("unexpected log config: %+v", cfg)
	}
	if cfg.Index == nil || *cfg.Index != 42 {
		t.Fatalf("unexpected static index: %+v", cfg.Index)
	}
	if cfg.Hash != nil {
		t.Fatalf("did not expect hash in static config: %+v", cfg.Hash)
	}
	if bs, err := json.Marshal(&cfg); err != nil || string(bs) != `{"id":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","index":42}` {
		t.Fatalf("unexpected marshal result %q (err=%v)", string(bs), err)
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

func TestEndorsementValidatorAcceptsFalseEndClaim(t *testing.T) {
	token := NewClaims()
	now := time.Now()
	mustSetClaim(t, token, "ver", uint64(consts.V1))
	mustSetClaim(t, token, "iat", now)
	mustSetClaim(t, token, "nbf", now.Add(-time.Minute))
	mustSetClaim(t, token, "exp", now.Add(time.Hour))
	mustSetClaim(t, token, "prp", uint64(1))
	mustSetClaim(t, token, "key", make([]byte, 32))
	mustSetClaim(t, token, "end", false)

	if err := ValidateClaims(token, true); err != nil {
		t.Fatalf("expected end=false to validate as a legal boolean claim, got %v", err)
	}
}

func TestEndorsementValidatorReportsIllegalEndClaim(t *testing.T) {
	token := NewClaims()
	now := time.Now()
	mustSetClaim(t, token, "ver", uint64(consts.V1))
	mustSetClaim(t, token, "iat", now)
	mustSetClaim(t, token, "nbf", now.Add(-time.Minute))
	mustSetClaim(t, token, "exp", now.Add(time.Hour))
	mustSetClaim(t, token, "prp", uint64(1))
	mustSetClaim(t, token, "key", make([]byte, 32))
	mustSetClaim(t, token, "end", "false")

	err := ValidateClaims(token, true)
	if err == nil {
		t.Fatalf("expected illegal claim type error, got %v", err)
	}
}

func mustSetClaim(t *testing.T, token *Claims, name string, value any) {
	t.Helper()
	if v, ok := value.(time.Time); ok {
		value = v.Unix()
	}
	if label, ok := claimLabels[name]; ok {
		token.CWTClaims[label] = value
	} else {
		token.CWTClaims[name] = value
	}
}

func TestOIRejectsNonDomainAuthoritiesAndURIComponents(t *testing.T) {
	for _, oi := range []string{"https://example.test#fragment", "https://example.test#", "https://example.test?", "https://example.test?query", "https://example.test/", "https://user@example.test", "https://example.test:443", "https://EXAMPLE.test", "https://127.0.0.1", "https://[::1]", "https://*.example.test", "https://bad_.test", "https://-bad.test"} {
		if err := validateOI(oi); err == nil {
			t.Fatalf("accepted invalid OI %s", oi)
		}
	}
}
