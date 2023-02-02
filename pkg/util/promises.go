package util

// An interface to implement promises that can be created and fullfilled later.
type Promise[T any] interface {
	// Fullfil the promise. [Get] will unblock (when called already) or succeed
	// (when called later).
	Fulfill(T)
	// Cancel a promise. Subsequent calls to [Get] will return T's null value.
	Reject()
	// Return the value of the promise. Will only return the result the promise
	// was fullfilled with exactly once. Afterwards, it will return the null
	// value. Call will block on unfullfilled promise.
	Get() T
}

type promise[T any] struct {
	ch chan T
}

// Create a new promise.
func NewPromise[T any]() Promise[T] {
	p := promise[T]{ch: make(chan T, 1)}
	return &p
}

func (p *promise[T]) Fulfill(val T) {
	p.ch <- val
	close(p.ch)
}

func (p *promise[T]) Reject() {
	close(p.ch)
}

func (p *promise[T]) Get() T {
	return <-p.ch
}

// Return a promise that is already fullfilled with the given value.
func Fullfilled[T any](val T) Promise[T] {
	p := NewPromise[T]()
	p.Fulfill(val)
	return p
}

// Return a rejected promise.
func Rejected[T any]() Promise[T] {
	p := NewPromise[T]()
	p.Reject()
	return p
}
