package roots

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	stdx509 "crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/adem-wg/adem-proto/pkg/consts"
	"github.com/adem-wg/adem-proto/pkg/tokens"
)

func TestGetInclusionVerifierUsesVersionSpecificLogs(t *testing.T) {
	if key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatalf("could not generate log key: %v", err)
	} else if keyDER, err := stdx509.MarshalPKIXPublicKey(key.Public()); err != nil {
		t.Fatalf("could not marshal log key: %v", err)
	} else {
		resetKnownLogs()

		v1OnlyID := "v1-only"
		staticOnlyID := "static-only"
		v1Logs[v1OnlyID] = V1Log{KeyDER: keyDER, URL: "https://ct.example"}
		staticLogs[staticOnlyID] = StaticLog{KeyDER: keyDER, MonitoringURL: "file:///tmp/static-log"}

		if _, err := GetInclusionVerifier(&tokens.LogConfig{
			Ver:   consts.LogVersionV1,
			Id:    staticOnlyID,
			Hash:  &tokens.LeafHash{Raw: []byte{1, 2, 3}},
			Index: nil,
		}); !errors.Is(err, ErrUnknownLog) {
			t.Fatalf("expected ErrUnknownLog for v1 lookup in static logs, got %v", err)
		}

		var index int64 = 0
		if _, err := GetInclusionVerifier(&tokens.LogConfig{
			Ver:   consts.LogVersionStatic,
			Id:    v1OnlyID,
			Hash:  nil,
			Index: &index,
		}); !errors.Is(err, ErrUnknownLog) {
			t.Fatalf("expected ErrUnknownLog for static lookup in v1 logs, got %v", err)
		}
	}
}

func TestStoreLogsSeparatesV1AndStaticLogs(t *testing.T) {
	if key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatalf("could not generate log key: %v", err)
	} else if keyDER, err := stdx509.MarshalPKIXPublicKey(key.Public()); err != nil {
		t.Fatalf("could not marshal log key: %v", err)
	} else {
		resetKnownLogs()

		logIDHash := sha256.Sum256(keyDER)
		logID := base64.StdEncoding.EncodeToString(logIDHash[:])
		ll := map[string]any{
			"operators": []any{
				map[string]any{
					"name": "test",
					"logs": []any{
						map[string]any{
							"description": "v1 log",
							"log_id":      logID,
							"key":         base64.StdEncoding.EncodeToString(keyDER),
							"url":         "https://ct.example",
							"mmd":         0,
						},
					},
					"tiled_logs": []any{
						map[string]any{
							"description":    "static log",
							"log_id":         logID,
							"key":            base64.StdEncoding.EncodeToString(keyDER),
							"monitoring_url": "file:///tmp/static-log",
							"mmd":            0,
						},
					},
				},
			},
		}

		if rawJSON, err := json.Marshal(ll); err != nil {
			t.Fatalf("could not marshal log list: %v", err)
		} else if err := storeLogs(rawJSON); err != nil {
			t.Fatalf("could not store logs: %v", err)
		}

		if logInfo, err := GetV1Log(logID); err != nil {
			t.Fatalf("could not get v1 log: %v", err)
		} else if got, want := logInfo.URL, "https://ct.example"; got != want {
			t.Fatalf("unexpected v1 log url: got %q want %q", got, want)
		}

		if logInfo, err := GetStaticLog(logID); err != nil {
			t.Fatalf("could not get static log: %v", err)
		} else if got, want := logInfo.MonitoringURL, "file:///tmp/static-log"; got != want {
			t.Fatalf("unexpected static monitoring url: got %q want %q", got, want)
		}
	}
}
