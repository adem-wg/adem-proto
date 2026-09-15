package tokens

import (
	"testing"

	"github.com/adem-wg/adem-proto/pkg/ident"
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

func TestVerifyPurposeConstraints(t *testing.T) {
	for emblem := uint64(0); emblem <= 32; emblem++ {
		for endorsement := uint64(0); endorsement <= 32; endorsement++ {
			e, a := NewClaims(), NewClaims()
			mustSetClaim(t, e, "prp", emblem)
			mustSetClaim(t, a, "prp", endorsement)
			valid := emblem >= 1 && emblem <= 31 && endorsement >= 1 && endorsement <= 31 && emblem&endorsement == emblem
			if err := VerifyConstraints(e, a); (err == nil) != valid {
				t.Fatalf("emblem %d, endorsement %d: %v", emblem, endorsement, err)
			}
		}
	}
	if err := VerifyConstraints(NewClaims(), NewClaims()); err == nil {
		t.Fatal("accepted missing purposes")
	}
}

func TestLegacyAssetMatchingUnchanged(t *testing.T) {
	emblem := NewClaims()
	mustSetClaim(t, emblem, "assets", []string{"api.example.com"})
	for _, tc := range []struct {
		assets Assets
		want   bool
	}{
		{nil, true}, {Assets{}, false},
		{Assets{parseAI(t, "*.example.com")}, true},
		{Assets{parseAI(t, "other.com")}, false},
	} {
		if got := checkAssetConstraint(emblem, EmblemConstraints{Assets: tc.assets}); got != tc.want {
			t.Fatalf("got %v, want %v", got, tc.want)
		}
	}
}
