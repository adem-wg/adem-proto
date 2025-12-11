package util

import "testing"

func TestB64Dec(t *testing.T) {
	if out, err := B64Dec([]byte("YWJj")); err != nil {
		t.Fatalf("expected decode to succeed, got error: %v", err)
	} else if string(out) != "abc" {
		t.Fatalf("unexpected decode result: %q", string(out))
	}
}

func TestB64DecInvalid(t *testing.T) {
	if _, err := B64Dec([]byte("%%%")); err == nil {
		t.Fatalf("expected invalid input to error")
	}
}
