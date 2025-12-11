package ident

import "testing"

func TestParseAIDomain(t *testing.T) {
	aiStr := "example.com"
	if ai, err := ParseAI(aiStr); err != nil {
		t.Fatalf("parse ai: %v", err)
	} else if ai.String() != aiStr {
		t.Fatalf("unexpected string form: %s", ai.String())
	}
}

func TestParseAIIPv6AndPrefix(t *testing.T) {
	ipStr := "[2001:db8::1]"
	if ip, err := ParseAI(ipStr); err != nil {
		t.Fatalf("parse ipv6: %v", err)
	} else if ip.String() != ipStr {
		t.Fatalf("unexpected ipv6 string: %s", ip.String())
	}

	prefixStr := "[2001:db8::/64]"
	if prefix, err := ParseAI(prefixStr); err != nil {
		t.Fatalf("parse prefix: %v", err)
	} else if prefix.String() != prefixStr {
		t.Fatalf("unexpected prefix string: %s", prefix.String())
	}
}

func TestParseAIWildcardRules(t *testing.T) {
	if _, err := ParseAI("a.*.example.com"); err != ErrWildcard {
		t.Fatalf("expected ErrWildcard for mid-label wildcard, got %v", err)
	}

	if _, err := ParseAI(""); err != ErrIllegalAI {
		t.Fatalf("expected ErrIllegalAI for empty input, got %v", err)
	}

	wildcardAi := "*.example.com"
	if ai, err := ParseAI(wildcardAi); err != nil {
		t.Fatalf("parse wildcard: %v", err)
	} else if ai.String() != wildcardAi {
		t.Fatalf("unexpected wildcard string: %s", ai.String())
	}
}

func TestMoreGeneral(t *testing.T) {
	general, _ := ParseAI("*.example.com")
	specific, _ := ParseAI("api.example.com")
	if !general.MoreGeneral(specific) {
		t.Fatalf("expected wildcard to cover specific subdomain")
	} else if general.MoreGeneral(&AI{domain: []string{"other", "com"}}) {
		t.Fatalf("expected wildcard to not cover unrelated domain")
	}

	network, _ := ParseAI("[192.0.2.0/24]")
	addr, _ := ParseAI("[192.0.2.10]")
	if !network.MoreGeneral(addr) {
		t.Fatalf("expected network to cover address")
	}
}
