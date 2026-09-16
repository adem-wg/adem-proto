package args

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

func TestLoadKeysRequiresOneFormat(t *testing.T) {
	if _, err := LoadKeys("keys.cbor", "keys.pem"); !errors.Is(err, ErrMultipleKeyFiles) {
		t.Fatalf("LoadKeys with both formats returned %v, want %v", err, ErrMultipleKeyFiles)
	}
	if _, err := LoadKeys("", ""); !errors.Is(err, ErrEmptyPath) {
		t.Fatalf("LoadKeys without a file returned %v, want %v", err, ErrEmptyPath)
	}
}

func TestLoadKeysFromCBORArray(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.cbor")
	want := make([]*cose.Key, 0, 2)
	for range 2 {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generating key: %v", err)
		}
		key, err := cose.NewKeyFromPrivate(privateKey)
		if err != nil {
			t.Fatalf("converting key to COSE: %v", err)
		}
		key.Algorithm = cose.AlgorithmES256
		want = append(want, key)
	}
	raw, err := cbor.Marshal(want)
	if err != nil {
		t.Fatalf("encoding COSE key array: %v", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("writing key array: %v", err)
	}

	keys, err := LoadKeys(path, "")
	if err != nil {
		t.Fatalf("loading key array: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("loaded %d keys, want 2", len(keys))
	}
	for _, key := range keys {
		if key.Algorithm != cose.AlgorithmES256 {
			t.Fatalf("key algorithm = %s, want ES256", key.Algorithm)
		}
	}
}
