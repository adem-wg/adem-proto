package tokens

import (
	"encoding/json"
	"testing"

	"github.com/adem-wg/adem-proto/pkg/consts"
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

func TestValidateOI(t *testing.T) {
	if err := validateOI("https://example.com"); err != nil {
		t.Fatalf("expected valid OI, got %v", err)
	} else if err := validateOI("http://example.com"); err == nil {
		t.Fatalf("expected invalid scheme to fail validation")
	} else if err := validateOI("https://example.com/path"); err == nil {
		t.Fatalf("expected path to make OI invalid")
	}
}
