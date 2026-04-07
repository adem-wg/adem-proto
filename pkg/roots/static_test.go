package roots

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	stdx509 "crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/sunlight"
	"github.com/adem-wg/adem-proto/pkg/tokens"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

func TestVerifyBindingCertsStatic(t *testing.T) {
	logKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("could not generate log key: %v", err)
	}
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("could not generate root key: %v", err)
	}

	rootJWK, err := jwk.Import(rootKey.Public())
	if err != nil {
		t.Fatalf("could not import root key: %v", err)
	}
	if err := rootJWK.Set("alg", jwa.ES256()); err != nil {
		t.Fatalf("could not set root key algorithm: %v", err)
	}

	kid, err := tokens.CalcKID(rootJWK)
	if err != nil {
		t.Fatalf("could not calculate kid: %v", err)
	}

	issuerHost := "example.org"
	entryCert, err := createBindingCert([]string{
		issuerHost,
		kid + ".adem-configuration." + issuerHost,
	})
	if err != nil {
		t.Fatalf("could not create binding certificate: %v", err)
	}

	monitoringDir := t.TempDir()
	logID, err := writeStaticLog(monitoringDir, "log.example/static", logKey, entryCert)
	if err != nil {
		t.Fatalf("could not write static log: %v", err)
	}

	resetKnownLogs()
	if err := storeLogs(staticLogListJSON(logID, logKey.Public(), monitoringDir)); err != nil {
		t.Fatalf("could not store logs: %v", err)
	}

	index := tokens.LeafIndex{Value: 0}
	results := VerifyBindingCerts("https://"+issuerHost, rootJWK, []*tokens.LogConfig{{
		Ver:   tokens.LogVersionStatic,
		Id:    logID,
		Index: &index,
	}})
	if len(results) != 1 {
		t.Fatalf("expected exactly one result, got %d", len(results))
	}
	if !results[0].Ok {
		t.Fatalf("expected static binding verification to succeed: %+v", results[0])
	}
	if !strings.HasPrefix(results[0].LogURL, "file://") {
		t.Fatalf("unexpected log url: %s", results[0].LogURL)
	}
}

func createBindingCert(dnsNames []string) ([]byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	template := &stdx509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: dnsNames[0],
		},
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Unix(86400, 0),
		DNSNames:     dnsNames,
		KeyUsage:     stdx509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []stdx509.ExtKeyUsage{stdx509.ExtKeyUsageServerAuth},
		SubjectKeyId: []byte{1, 2, 3, 4},
	}

	return stdx509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
}

func writeStaticLog(dir string, origin string, logKey *ecdsa.PrivateKey, certDER []byte) (string, error) {
	entry := &sunlight.LogEntry{
		Certificate: certDER,
		LeafIndex:   0,
		Timestamp:   1700000000000,
	}
	dataTile := sunlight.AppendTileLeaf(nil, entry)
	recordHash := tlog.RecordHash(entry.MerkleTreeLeaf())

	if err := writeStaticAsset(dir, sunlight.TilePath(tlog.Tile{H: sunlight.TileHeight, L: -1, N: 0, W: 1}), dataTile); err != nil {
		return "", err
	}
	if err := writeStaticAsset(dir, sunlight.TilePath(tlog.Tile{H: sunlight.TileHeight, L: 0, N: 0, W: 1}), recordHash[:]); err != nil {
		return "", err
	}

	timestamp := uint64(1700000000000)
	sth := ct.SignedTreeHead{
		Version:        ct.V1,
		TreeSize:       1,
		Timestamp:      timestamp,
		SHA256RootHash: ct.SHA256Hash(recordHash),
	}
	sthInput, err := ct.SerializeSTHSignatureInput(sth)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(sthInput)
	sig, err := ecdsa.SignASN1(rand.Reader, logKey, digest[:])
	if err != nil {
		return "", err
	}
	treeHeadSig, err := tls.Marshal(tls.DigitallySigned{
		Algorithm: tls.SignatureAndHashAlgorithm{
			Hash:      tls.SHA256,
			Signature: tls.ECDSA,
		},
		Signature: sig,
	})
	if err != nil {
		return "", err
	}
	signer, err := sunlight.NewRFC6962InjectedSigner(origin, logKey.Public(), treeHeadSig, int64(timestamp))
	if err != nil {
		return "", err
	}
	checkpoint, err := note.Sign(&note.Note{
		Text: sunlight.FormatCheckpoint(sunlight.Checkpoint{
			Origin: origin,
			Tree:   tlog.Tree{N: 1, Hash: recordHash},
		}),
	}, signer)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, "checkpoint"), checkpoint, 0o644); err != nil {
		return "", err
	}

	pubDER, err := stdx509.MarshalPKIXPublicKey(logKey.Public())
	if err != nil {
		return "", err
	}
	logID := sha256.Sum256(pubDER)
	return base64.StdEncoding.EncodeToString(logID[:]), nil
}

func writeStaticAsset(root string, rel string, data []byte) error {
	path := filepath.Join(append([]string{root}, strings.Split(rel, "/")...)...)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func staticLogListJSON(logID string, publicKey any, monitoringDir string) []byte {
	pubDER, err := stdx509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		panic(err)
	}

	ll := map[string]any{
		"operators": []any{
			map[string]any{
				"name": "test",
				"tiled_logs": []any{
					map[string]any{
						"description":    "static log",
						"log_id":         logID,
						"key":            base64.StdEncoding.EncodeToString(pubDER),
						"submission_url": "https://log.example/static/",
						"monitoring_url": "file://" + monitoringDir,
						"mmd":            0,
					},
				},
			},
		},
	}

	bs, err := json.Marshal(ll)
	if err != nil {
		panic(err)
	}
	return bs
}

func resetKnownLogs() {
	logMapLock.Lock()
	defer logMapLock.Unlock()
	ctLogs = make(map[string]CTLog)
}
