package args

import (
	"bytes"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func TestDecodeTokensFromCBORArray(t *testing.T) {
	want := [][]byte{{0xd2, 0x84, 0x01}, {0xd2, 0x84, 0x02}}
	raw, err := cbor.Marshal(want)
	if err != nil {
		t.Fatalf("encoding token array: %v", err)
	}

	got, err := DecodeTokens(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("decoding token array: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("decoded %d tokens, want %d", len(got), len(want))
	}
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			t.Fatalf("token %d = %x, want %x", i, got[i], want[i])
		}
	}
}

func TestDecodeTokensRejectsConcatenatedObjects(t *testing.T) {
	raw := []byte{0xd2, 0x84, 0x01}
	if _, err := DecodeTokens(bytes.NewReader(raw)); err == nil {
		t.Fatal("decoding a standalone token succeeded, want a CBOR-array error")
	}
}
