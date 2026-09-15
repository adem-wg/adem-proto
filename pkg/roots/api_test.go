package roots

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/adem-wg/adem-proto/pkg/tokens"
)

func TestLookupMethodMustMatchTrustedDirectory(t *testing.T) {
	sk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&sk.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	idA := make([]byte, 32)
	idA[0] = 41
	idB := make([]byte, 32)
	idB[0] = 42
	classic, tiled := base64.StdEncoding.EncodeToString(idA), base64.StdEncoding.EncodeToString(idB)
	logMapLock.Lock()
	oldV1, oldStatic := v1Logs, staticLogs
	v1Logs = map[string]V1Log{classic: {KeyDER: der, URL: "https://classic.invalid/"}}
	staticLogs = map[string]StaticLog{tiled: {KeyDER: der, MonitoringURL: "https://tiled.invalid/"}}
	logMapLock.Unlock()
	t.Cleanup(func() { logMapLock.Lock(); defer logMapLock.Unlock(); v1Logs, staticLogs = oldV1, oldStatic })
	hash := &tokens.LeafHash{Raw: make([]byte, 32)}
	index := uint64(0)
	if verifier, err := GetInclusionVerifier(&tokens.LogConfig{Id: classic, Hash: hash}); err != nil {
		t.Fatal(err)
	} else if _, ok := verifier.(*v1InclusionVerifier); !ok {
		t.Fatal("wrong classic verifier")
	}
	if verifier, err := GetInclusionVerifier(&tokens.LogConfig{Id: tiled, Index: &index}); err != nil {
		t.Fatal(err)
	} else if _, ok := verifier.(*staticInclusionVerifier); !ok {
		t.Fatal("wrong tiled verifier")
	}
	for _, cfg := range []*tokens.LogConfig{{Id: classic, Index: &index}, {Id: tiled, Hash: hash}} {
		if _, err := GetInclusionVerifier(cfg); !errors.Is(err, ErrUnknownLog) {
			t.Fatalf("lookup method did not match directory: %v", err)
		}
	}
}
