package util

type Elem[T comparable] interface {
	ToComparable() T
}

type Set[T comparable] interface {
	Has(Elem[T]) Elem[T]
	HasKey(T) Elem[T]
	Add(Elem[T])
	Rm(Elem[T]) Elem[T]
	Size() int
}

type set[T comparable] map[T]Elem[T]

func MkSet[T comparable]() Set[T] {
	m := make(set[T])
	return &m
}

func (s *set[T]) Has(val Elem[T]) Elem[T] {
	e := (*s)[val.ToComparable()]
	return e
}

func (s *set[T]) HasKey(val T) Elem[T] {
	e := (*s)[val]
	return e
}

func (s *set[T]) Add(val Elem[T]) {
	(*s)[val.ToComparable()] = val
}

func (s *set[T]) Rm(val Elem[T]) Elem[T] {
	e := (*s)[val.ToComparable()]
	delete(*s, val.ToComparable())
	return e
}

func (s *set[T]) Size() int {
	return len(*s)
}
