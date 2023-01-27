package util

type Promise[T any] interface {
	Fulfill(T)
	Reject()
	Get() T
}

type promise[T any] struct {
	ch chan T
}

func NewPromise[T any]() Promise[T] {
	p := promise[T]{ch: make(chan T, 1)}
	return &p
}

func (p *promise[T]) Fulfill(val T) {
	p.ch <- val
}

func (p *promise[T]) Reject() {
	close(p.ch)
}

func (p *promise[T]) Get() T {
	return <-p.ch
}

func Resolve[T any](val T) Promise[T] {
	p := NewPromise[T]()
	p.Fulfill(val)
	return p
}
