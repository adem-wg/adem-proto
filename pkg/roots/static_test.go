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
	"github.com/adem-wg/adem-proto/pkg/consts"
	"github.com/adem-wg/adem-proto/pkg/tokens"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

func TestVerifyBindingCertsStatic(t *testing.T) {
	if logKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatalf("could not generate log key: %v", err)
	} else if rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatalf("could not generate root key: %v", err)
	} else if rootJWK, err := jwk.Import(rootKey.Public()); err != nil {
		t.Fatalf("could not import root key: %v", err)
	} else if err := rootJWK.Set("alg", jwa.ES256()); err != nil {
		t.Fatalf("could not set root key algorithm: %v", err)
	} else if kid, err := tokens.CalcKID(rootJWK); err != nil {
		t.Fatalf("could not calculate kid: %v", err)
	} else {
		issuerHost := "example.org"
		if entryCert, err := createBindingCert([]string{
			issuerHost,
			kid + ".adem-configuration." + issuerHost,
		}); err != nil {
			t.Fatalf("could not create binding certificate: %v", err)
		} else {
			monitoringDir := t.TempDir()
			if logID, err := writeStaticLog(monitoringDir, "log.example/static", logKey, entryCert); err != nil {
				t.Fatalf("could not write static log: %v", err)
			} else {
				resetKnownLogs()
				if err := storeLogs(staticLogListJSON(logID, logKey.Public(), monitoringDir)); err != nil {
					t.Fatalf("could not store logs: %v", err)
				} else {
					var index int64 = 0
					results := VerifyBindingCerts("https://"+issuerHost, rootJWK, []*tokens.LogConfig{{
						Ver:   consts.LogVersionStatic,
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
			}
		}
	}
}

func createBindingCert(dnsNames []string) ([]byte, error) {
	if key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		return nil, err
	} else {
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
	if sthInput, err := ct.SerializeSTHSignatureInput(sth); err != nil {
		return "", err
	} else {
		digest := sha256.Sum256(sthInput)
		if sig, err := ecdsa.SignASN1(rand.Reader, logKey, digest[:]); err != nil {
			return "", err
		} else if treeHeadSig, err := tls.Marshal(tls.DigitallySigned{
			Algorithm: tls.SignatureAndHashAlgorithm{
				Hash:      tls.SHA256,
				Signature: tls.ECDSA,
			},
			Signature: sig,
		}); err != nil {
			return "", err
		} else if signer, err := sunlight.NewRFC6962InjectedSigner(origin, logKey.Public(), treeHeadSig, int64(timestamp)); err != nil {
			return "", err
		} else if checkpoint, err := note.Sign(&note.Note{
			Text: sunlight.FormatCheckpoint(sunlight.Checkpoint{
				Origin: origin,
				Tree:   tlog.Tree{N: 1, Hash: recordHash},
			}),
		}, signer); err != nil {
			return "", err
		} else if err := os.WriteFile(filepath.Join(dir, "checkpoint"), checkpoint, 0o644); err != nil {
			return "", err
		} else if pubDER, err := stdx509.MarshalPKIXPublicKey(logKey.Public()); err != nil {
			return "", err
		} else {
			logID := sha256.Sum256(pubDER)
			return base64.StdEncoding.EncodeToString(logID[:]), nil
		}
	}
}

func writeStaticAsset(root string, rel string, data []byte) error {
	path := filepath.Join(append([]string{root}, strings.Split(rel, "/")...)...)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func staticLogListJSON(logID string, publicKey any, monitoringDir string) []byte {
	if pubDER, err := stdx509.MarshalPKIXPublicKey(publicKey); err != nil {
		panic(err)
	} else {
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

		if bs, err := json.Marshal(ll); err != nil {
			panic(err)
		} else {
			return bs
		}
	}
}

func resetKnownLogs() {
	logMapLock.Lock()
	defer logMapLock.Unlock()
	ctLogs = make(map[string]CTLog)
}
