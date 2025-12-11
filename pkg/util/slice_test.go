package util

import "testing"

func TestContains(t *testing.T) {
	if !Contains([]string{"a", "b", "c"}, "b") {
		t.Fatalf("expected slice to contain element")
	} else if Contains([]int{1, 2, 3}, 4) {
		t.Fatalf("expected slice to not contain element")
	}
}

func TestInsertWithinBounds(t *testing.T) {
	s := []int{1, 2, 3}
	res := Insert(s, 1, 9)

	if len(res) != 3 {
		t.Fatalf("expected len 3, got %d", len(res))
	} else if res[1] != 9 {
		t.Fatalf("expected value at index 1 to be 9, got %d", res[1])
	}
}

func TestInsertBeyondLength(t *testing.T) {
	s := []int{1, 2}
	res := Insert(s, 4, 5)

	if len(res) != 5 {
		t.Fatalf("expected len 5, got %d", len(res))
	}
	expected := []int{1, 2, 0, 0, 5}
	for i, v := range expected {
		if res[i] != v {
			t.Fatalf("expected %v at index %d, got %v", expected, i, res[i])
		}
	}
}
