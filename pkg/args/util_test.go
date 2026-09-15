package args

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/adem-wg/adem-proto/pkg/tokens"
	"github.com/veraison/go-cose"
)

func TestPEMKeyFormats(t *testing.T) {
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sec1, err := x509.MarshalECPrivateKey(ec)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(ed)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(&ec.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &ec.PublicKey, ec)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		der     []byte
		alg     cose.Algorithm
		private bool
	}{
		{"EC PRIVATE KEY", sec1, cose.AlgorithmES256, true},
		{"PRIVATE KEY", pkcs8, cose.AlgorithmEdDSA, true},
		{"PUBLIC KEY", public, cose.AlgorithmES256, false},
		{"CERTIFICATE", der, cose.AlgorithmES256, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keys, err := ParsePEMKeys(pem.EncodeToMemory(&pem.Block{Type: tc.name, Bytes: tc.der}))
			if err != nil {
				t.Fatal(err)
			}
			if len(keys) != 1 {
				t.Fatalf("got %d keys", len(keys))
			}
			for kid, key := range keys {
				if key.Algorithm != tc.alg {
					t.Fatal("incorrect algorithm")
				}
				if expected, err := tokens.CalcKID(key); err != nil || kid != expected {
					t.Fatal("incorrect key index")
				}
				if _, err := key.PrivateKey(); (err == nil) != tc.private {
					t.Fatal("incorrect private material")
				}
			}
		})
	}
	bundle := append(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})...)
	if keys, err := ParsePEMKeys(bundle); err != nil || len(keys) != 2 {
		t.Fatalf("bundle: %v", err)
	}
	for _, invalid := range [][]byte{nil, []byte(`{"kty":"EC"}`), []byte(`{"keys":[]}`), []byte("garbage"), append(bundle, []byte("garbage")...), pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: pkcs8})} {
		if _, err := ParsePEMKeys(invalid); err == nil {
			t.Fatalf("accepted invalid or unsupported key input %q", invalid)
		}
	}
}
