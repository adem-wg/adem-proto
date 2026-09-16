package args

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/adem-wg/adem-proto/pkg/tokens"
)

func TestLoadClaimsProtoFromJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "claims.json")
	raw := []byte(`{
		"ver": 1,
		"iss": "https://example.com",
		"prp": 1,
		"assets": ["example.com"]
	}`)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("writing claims prototype: %v", err)
	}

	previousPath := protoPath
	protoPath = path
	t.Cleanup(func() { protoPath = previousPath })

	claims := LoadClaimsProto()
	if claims.Ver != 1 {
		t.Fatalf("version = %d, want 1", claims.Ver)
	}
	if claims.Iss != "https://example.com" {
		t.Fatalf("issuer = %q, want https://example.com", claims.Iss)
	}
	if claims.Prp != tokens.RedCrProtective {
		t.Fatalf("purpose = %d, want %d", claims.Prp, tokens.RedCrProtective)
	}
	if len(claims.Assets) != 1 || claims.Assets[0] != "example.com" {
		t.Fatalf("assets = %v, want [example.com]", claims.Assets)
	}
}
