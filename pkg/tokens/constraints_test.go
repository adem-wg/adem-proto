package tokens

import (
	"testing"
	"time"

	"github.com/adem-wg/adem-proto/pkg/ident"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

func parseAI(t *testing.T, raw string) *ident.AI {
	t.Helper()
	if ai, err := ident.ParseAI(raw); err != nil {
		t.Fatalf("parse ai %q: %v", raw, err)
		return nil
	} else {
		return ai
	}
}

func mkEmblemToken(t *testing.T, emb EmblemConstraints, bearers []*ident.AI, nbf, exp time.Time) jwt.Token {
	t.Helper()
	tok := jwt.New()
	if err := tok.Set("emb", emb); err != nil {
		t.Fatalf("set emb: %v", err)
	} else if err := tok.Set("bearers", bearers); err != nil {
		t.Fatalf("set bearers: %v", err)
	} else if err := tok.Set(jwt.NotBeforeKey, nbf); err != nil {
		t.Fatalf("set nbf: %v", err)
	} else if err := tok.Set(jwt.ExpirationKey, exp); err != nil {
		t.Fatalf("set exp: %v", err)
	}
	return tok
}

func mkEndorsementToken(t *testing.T, emb *EmblemConstraints) jwt.Token {
	t.Helper()
	tok := jwt.New()
	if emb != nil {
		if err := tok.Set("emb", *emb); err != nil {
			t.Fatalf("set emb: %v", err)
		}
	}
	return tok
}

func TestVerifyConstraintsNoConstraints(t *testing.T) {
	endorsement := mkEndorsementToken(t, nil)
	emblem := jwt.New()

	if err := VerifyConstraints(emblem, endorsement); err != nil {
		t.Fatalf("expected no error when endorsement has no constraints, got %v", err)
	}
}

func TestVerifyConstraintsAssetMismatch(t *testing.T) {
	constraints := EmblemConstraints{
		Assets: []*ident.AI{parseAI(t, "example.com")},
	}
	endorsement := mkEndorsementToken(t, &constraints)
	emblem := jwt.New()
	if err := emblem.Set("bearers", []*ident.AI{parseAI(t, "other.com")}); err != nil {
		t.Fatalf("set bearers: %v", err)
	} else if err := VerifyConstraints(emblem, endorsement); err != ErrAssetConstraint {
		t.Fatalf("expected ErrAssetConstraint, got %v", err)
	}
}

func TestVerifyConstraintsPurposeMismatch(t *testing.T) {
	pEnd := Protective
	pEmb := Indicative
	endConstraints := EmblemConstraints{Purpose: &pEnd}
	endorsement := mkEndorsementToken(t, &endConstraints)

	embConstraints := EmblemConstraints{Purpose: &pEmb}
	now := time.Now()
	emblem := mkEmblemToken(t, embConstraints, []*ident.AI{parseAI(t, "example.com")}, now, now.Add(time.Minute))

	if err := VerifyConstraints(emblem, endorsement); err != ErrPrpConstraint {
		t.Fatalf("expected ErrPrpConstraint, got %v", err)
	}
}

func TestVerifyConstraintsDistributionMismatch(t *testing.T) {
	dEnd := TLS
	dEmb := DNS
	endConstraints := EmblemConstraints{Distribution: &dEnd}
	endorsement := mkEndorsementToken(t, &endConstraints)

	embConstraints := EmblemConstraints{Distribution: &dEmb}
	now := time.Now()
	emblem := mkEmblemToken(t, embConstraints, []*ident.AI{parseAI(t, "example.com")}, now, now.Add(time.Minute))

	if err := VerifyConstraints(emblem, endorsement); err != ErrDstConstraint {
		t.Fatalf("expected ErrDstConstraint, got %v", err)
	}
}

func TestVerifyConstraintsWindowExceeded(t *testing.T) {
	wnd := 5
	endConstraints := EmblemConstraints{Window: &wnd}
	endorsement := mkEndorsementToken(t, &endConstraints)

	embConstraints := EmblemConstraints{}
	nbf := time.Now()
	exp := nbf.Add(10 * time.Second)
	emblem := mkEmblemToken(t, embConstraints, []*ident.AI{parseAI(t, "example.com")}, nbf, exp)

	if err := VerifyConstraints(emblem, endorsement); err != ErrWndConstraint {
		t.Fatalf("expected ErrWndConstraint, got %v", err)
	}
}

func TestVerifyConstraintsSuccess(t *testing.T) {
	p := Protective | Indicative
	d := DNS | TLS
	wnd := 60
	endConstraints := EmblemConstraints{
		Purpose:      &p,
		Distribution: &d,
		Window:       &wnd,
		Assets:       []*ident.AI{parseAI(t, "*.example.com")},
	}
	endorsement := mkEndorsementToken(t, &endConstraints)

	embConstraints := EmblemConstraints{
		Purpose:      &p,
		Distribution: &d,
		Assets:       []*ident.AI{parseAI(t, "api.example.com")},
	}
	nbf := time.Now()
	exp := nbf.Add(30 * time.Second)
	emblem := mkEmblemToken(t, embConstraints, []*ident.AI{parseAI(t, "api.example.com")}, nbf, exp)

	if err := VerifyConstraints(emblem, endorsement); err != nil {
		t.Fatalf("expected constraints to verify, got %v", err)
	}
}
