package roots

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/adem-wg/adem-proto/pkg/tokens"
	"github.com/veraison/go-cose"
)

func TestBindingNames(t *testing.T) {
	sk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := cose.NewKeyFromPrivate(sk)
	if err != nil {
		t.Fatal(err)
	}
	key.Algorithm = cose.AlgorithmES256
	kid, err := tokens.CalcKID(key)
	if err != nil {
		t.Fatal(err)
	}
	q := CTQueryResult{subjects: []string{"adem-configuration.example.test", kid + ".adem-configuration.example.test"}}
	if err := VerifyBinding(q, "https://example.test", key); err != nil {
		t.Fatal(err)
	}
	q.subjects[0] = "example.test"
	if err := VerifyBinding(q, "https://example.test", key); err == nil {
		t.Fatal("accepted old binding names")
	}
}
