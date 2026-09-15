package tokens

import (
	"bytes"
	"slices"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

var MinimalEmblem = Claims{
	Ver:    1,
	Iss:    "https://example.com",
	Exp:    7,
	Nbf:    7,
	Prp:    RedCrProtective | CivilDefence,
	Assets: []string{"example.com"},
}

var True = true

var MinimalEndorsement = Claims{
	Ver: 1,
	Iss: "https://example.com",
	Sub: "https://example.com",
	Exp: 7,
	Nbf: 7,
	Prp: RedCrIndicative | BlueShield,
	Key: []byte{0, 1, 2},
	End: &True,
}

// TODO: Test for complete endorsement including logs

func TestEncodeDecodeEmblem(t *testing.T) {
	if embBs, err := cbor.Marshal(MinimalEmblem); err != nil {
		t.Fatalf("marshalling emblem failed: %v", err)
	} else if emb, err := DecodePayload(embBs); err != nil {
		t.Fatalf("unmarshaling emblem failed: %v", err)
	} else if emb.Ver != 1 {
		t.Fatalf("emb.Ver is %v but expected 1", emb.Ver)
	} else if emb.Iss != MinimalEmblem.Iss {
		t.Fatalf("emb.Iss is %v but expected %v", emb.Iss, MinimalEmblem.Iss)
	} else if emb.Sub != "" {
		t.Fatalf("emb.Sub is %v but expected empty string", emb.Sub)
	} else if emb.Exp != MinimalEmblem.Exp {
		t.Fatalf("emb.Exp is %v but expected %v", emb.Exp, MinimalEmblem.Exp)
	} else if emb.Nbf != MinimalEmblem.Nbf {
		t.Fatalf("emb.Nbf is %v but expected %v", emb.Nbf, MinimalEmblem.Nbf)
	} else if emb.Iat != 0 {
		t.Fatalf("emb.Iat is %v but expected 0", emb.Iat)
	} else if emb.Prp != MinimalEmblem.Prp {
		t.Fatalf("emb.Prp is %v but expected %v", emb.Prp, MinimalEmblem.Prp)
	} else if !slices.Equal(emb.Assets, MinimalEmblem.Assets) {
		t.Fatalf("emb.Assets is %v but expected %v", emb.Assets, MinimalEmblem.Assets)
	} else if emb.Key != nil {
		t.Fatal("emb.Key is defined but expected nil")
	} else if emb.End != nil {
		t.Fatal("emb.End is defined but expected nil")
	} else if emb.Log != nil {
		t.Fatal("emb.Log is defined but expected nil")
	}
}

func TestEncodeDecodeEndorsement(t *testing.T) {
	if endBs, err := cbor.Marshal(MinimalEndorsement); err != nil {
		t.Fatalf("marshalling endorsement failed: %v", err)
	} else if end, err := DecodePayload(endBs); err != nil {
		t.Fatalf("unmarshaling endorsement failed: %v", err)
	} else if end.Ver != 1 {
		t.Fatalf("end.Ver is %v but expected 1", end.Ver)
	} else if end.Iss != MinimalEndorsement.Iss {
		t.Fatalf("end.Iss is %v but expected %v", end.Iss, MinimalEndorsement.Iss)
	} else if end.Sub != MinimalEndorsement.Sub {
		t.Fatalf("end.Sub is %v but expected %v", end.Sub, MinimalEndorsement.Sub)
	} else if end.Exp != MinimalEndorsement.Exp {
		t.Fatalf("end.Exp is %v but expected %v", end.Exp, MinimalEndorsement.Exp)
	} else if end.Nbf != MinimalEndorsement.Nbf {
		t.Fatalf("end.Nbf is %v but expected %v", end.Nbf, MinimalEndorsement.Nbf)
	} else if end.Iat != 0 {
		t.Fatalf("end.Iat is %v but expected 0", end.Iat)
	} else if end.Prp != MinimalEndorsement.Prp {
		t.Fatalf("end.Prp is %v but expected %v", end.Prp, MinimalEndorsement.Prp)
	} else if end.Assets != nil {
		t.Fatal("end.Assets is defined but expected nil")
	} else if !bytes.Equal(end.Key, MinimalEndorsement.Key) {
		t.Fatalf("end.Key is %v but expected %v", end.Key, MinimalEmblem.Key)
	} else if *end.End != *MinimalEndorsement.End {
		t.Fatalf("end.End is %v but expected %v", end.End, MinimalEmblem.End)
	} else if end.Log != nil {
		t.Fatal("end.Log is defined but expected nil")
	}
}
