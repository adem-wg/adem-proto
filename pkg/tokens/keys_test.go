package tokens_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/adem-wg/adem-proto/pkg/tokens"
	"github.com/veraison/go-cose"
)

// Source: https://www.rfc-editor.org/info/rfc9679/#name-example
const key = "A50102200121582065EDA5A12577C2BAE829437FE338701A10AAA375E1BB5B5DE108DE439C08551D2258201E52ED75701163F7F9E40DDF9F341B3DC9BA860AF7E0CA7CA7E9EECD0084D19C025820496BD8AFADF307E5B08C64B0421BF9DC01528A344A43BDA88FADD1669DA253EC"
const digest = "496bd8afadf307e5b08c64b0421bf9dc01528a344a43bda88fadd1669da253ec"

func TestThumbprint(t *testing.T) {
	k := cose.Key{}
	if keyBs, err := hex.DecodeString(key); err != nil {
		t.Fatalf("could not decode hex: %v", err)
	} else if digestBs, err := hex.DecodeString(digest); err != nil {
		t.Fatalf("could not decode hex: %v", err)
	} else if err := (&k).UnmarshalCBOR(keyBs); err != nil {
		t.Fatalf("could not unmarshal key: %v", err)
	} else if kid, err := tokens.COSEThumbprint(&k); err != nil {
		t.Fatalf("could not compute thumbprint: %v", err)
	} else if !bytes.Equal(kid, digestBs) {
		t.Fatal("thumbprint mismatch")
	}
}
