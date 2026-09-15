package tokens

import (
	"math"
	"testing"
	"time"

	"github.com/veraison/go-cose"
)

func TestNativeClaimsAndPrototypePrecision(t *testing.T) {
	c, err := ParseClaims([]byte(`{"ver":1,"prp":3,"nbf":100.25,"exp":200.5,"iss":"https://example.test","assets":["example.test"]}`))
	if err != nil {
		t.Fatal(err)
	}
	payload, _, err := EncodeClaims(c, false)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeClaims(payload, false)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.CWTClaims[cose.CWTClaimNotBefore] != 100.25 || decoded.CWTClaims[cose.CWTClaimExpirationTime] != 200.5 {
		t.Fatal("fractional NumericDates lost")
	}
	if _, present := decoded.CWTClaims["nbf"]; present {
		t.Fatal("registered claim used text label")
	}
	for _, tc := range []struct {
		now   time.Time
		valid bool
	}{
		{time.Unix(100, 249999999), false}, {time.Unix(100, 250000000), true},
		{time.Unix(200, 499999999), true}, {time.Unix(200, 500000000), false},
	} {
		if err := decoded.ValidateTime(tc.now); (err == nil) != tc.valid {
			t.Fatalf("boundary %v: %v", tc.now, err)
		}
	}
	// The previous JSON intermediary could round integers larger than 2^53.
	large, err := ParseClaims([]byte(`{"ver":1,"prp":1,"nbf":9007199254740993,"exp":9007199254740995,"end":false,"key":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`))
	if err != nil {
		t.Fatal(err)
	}
	if large.CWTClaims[cose.CWTClaimNotBefore] != int64(9007199254740993) {
		t.Fatal("prototype integer rounded")
	}
	payload, _, err = EncodeClaims(large, true)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err = decodeClaims(payload, true)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.CWTClaims[cose.CWTClaimNotBefore] != uint64(9007199254740993) {
		t.Fatal("wire integer rounded")
	}
	if key, ok := decoded.CWTClaims["key"].([]byte); !ok || len(key) != 32 {
		t.Fatal("thumbprint is not a native byte string")
	}
}

func TestNativeClaimTypeRejection(t *testing.T) {
	for _, input := range []string{
		`null`, `[]`, `{"prp":null}`, `{"prp":"1"}`, `{"ver":1.0}`,
		`{"nbf":"100"}`, `{"exp":1e999}`, `{"key":"invalid"}`,
		`{"emb":{}}`, `{"extension":true}`, `{"end":1}`,
	} {
		if _, err := ParseClaims([]byte(input)); err == nil {
			t.Fatalf("accepted %s", input)
		}
	}
	for _, value := range []any{nil, "1", true, math.NaN(), math.Inf(1), math.Inf(-1), uint64(math.MaxUint64)} {
		if _, err := NumericDate(value); err == nil {
			t.Fatalf("accepted NumericDate %#v", value)
		}
	}
}
