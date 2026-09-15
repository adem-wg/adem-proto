package main

import (
	"encoding/json"
	"testing"

	"filippo.io/sunlight"
	"github.com/adem-wg/adem-proto/pkg/tokens"
	ct "github.com/google/certificate-transparency-go"
)

func TestStaticConfigContainsIndexOnly(t *testing.T) {
	ext, err := sunlight.MarshalExtensions(sunlight.Extensions{LeafIndex: 0})
	if err != nil {
		t.Fatal(err)
	}
	sct := &ct.SignedCertificateTimestamp{Extensions: ext}
	cfg, err := mkCfg(nil, sct)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Index == nil || *cfg.Index != 0 || cfg.Hash != nil {
		t.Fatalf("wrong static lookup: %+v", cfg)
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	if len(fields) != 2 || fields["ver"] != nil {
		t.Fatalf("obsolete fields: %s", raw)
	}
	var parsed tokens.LogConfig
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}
}
