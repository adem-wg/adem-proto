package tokens

import (
	"encoding/base64"
	"encoding/json"
	"math"
	"testing"
)

func TestLogLookupFormats(t *testing.T) {
	id := make([]byte, 32)
	hash := make([]byte, 32)
	for _, entry := range []map[string]any{
		{"id": id, "hash": hash},
		{"id": id, "index": uint64(0)},
		{"id": id, "index": uint64(math.MaxUint64)},
	} {
		logs, err := decodeLogs([]any{entry})
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := encodeLogs(logs)
		if err != nil {
			t.Fatal(err)
		}
		actual := encoded[0].(map[string]any)
		if len(actual) != 2 {
			t.Fatalf("obsolete log fields: %v", actual)
		}
		if index, ok := entry["index"]; ok {
			if actual["index"] != index {
				t.Fatal("index lost precision or zero")
			}
		}
		raw, err := json.Marshal(logs)
		if err != nil {
			t.Fatal(err)
		}
		var parsed Log
		if err := json.Unmarshal(raw, &parsed); err != nil {
			t.Fatal(err)
		}
		if parsed[0].Id != base64.StdEncoding.EncodeToString(id) {
			t.Fatal("incorrect log id")
		}
	}
}

func TestRejectInvalidLogLookupFormats(t *testing.T) {
	id := make([]byte, 32)
	hash := make([]byte, 32)
	cases := map[string]map[string]any{
		"neither":        {"id": id},
		"both":           {"id": id, "hash": hash, "index": uint64(0)},
		"old version":    {"id": id, "hash": hash, "ver": "v1"},
		"negative index": {"id": id, "index": int64(-1)},
		"float index":    {"id": id, "index": float64(1)},
		"null index":     {"id": id, "index": nil},
		"string index":   {"id": id, "index": "1"},
		"short hash":     {"id": id, "hash": []byte{1}},
		"null hash":      {"id": id, "hash": nil},
		"short id":       {"id": []byte{1}, "index": uint64(0)},
	}
	for name, entry := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeLogs([]any{entry}); err == nil {
				t.Fatal("accepted invalid log")
			}
		})
	}
	if _, err := decodeLogs([]any{}); err == nil {
		t.Fatal("accepted empty log header")
	}
}
