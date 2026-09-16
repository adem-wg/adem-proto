package args

import (
	"bytes"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

func TestDecodeTokensFromCBORArray(t *testing.T) {
	want := []*cose.Sign1Message{
		{Payload: []byte("first"), Signature: []byte{1}},
		{Payload: []byte("second"), Signature: []byte{2}},
	}
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
		if !bytes.Equal(got[i].Payload, want[i].Payload) {
			t.Fatalf("token %d payload = %q, want %q", i, got[i].Payload, want[i].Payload)
		}
	}
}

func TestDecodeTokensRejectsConcatenatedObjects(t *testing.T) {
	message := &cose.Sign1Message{Payload: []byte("token"), Signature: []byte{1}}
	raw, err := message.MarshalCBOR()
	if err != nil {
		t.Fatalf("encoding token: %v", err)
	}
	if _, err := DecodeTokens(bytes.NewReader(raw)); err == nil {
		t.Fatal("decoding a standalone token succeeded, want a CBOR-array error")
	}
}
