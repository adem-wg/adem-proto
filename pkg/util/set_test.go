package util

import "testing"

func TestHasNilNoPanic(t *testing.T) {
	s := MkSet[int]()
	s.Has(nil)
}

func TestAddNilNoPanic(t *testing.T) {
	s := MkSet[int]()
	s.Add(nil)
}

func TestRmNilNoPanic(t *testing.T) {
	s := MkSet[int]()
	s.Rm(nil)
}
