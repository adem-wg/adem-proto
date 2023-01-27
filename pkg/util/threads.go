package util

import (
	"sync"
)

// Similar to [sync.WaitGroup], but maintains a count of running threads.
type ThreadCount struct {
	// Struct access lock
	lock sync.Mutex
	// Underlying [sync.WaitGroup]
	wg sync.WaitGroup
	// Counter of remaining threads
	count int
}

func NewThreadCount(numThreads int) *ThreadCount {
	tc := ThreadCount{count: numThreads}
	tc.wg.Add(numThreads)
	return &tc
}

// Register one thread as done.
func (tc *ThreadCount) Done() {
	tc.lock.Lock()
	defer tc.lock.Unlock()
	tc.wg.Done()
	tc.count -= 1
}

// How many threads are left running?
func (tc *ThreadCount) Running() int {
	tc.lock.Lock()
	defer tc.lock.Unlock()
	return tc.count
}

// Block until all threads terminated.
func (tc *ThreadCount) Wait() {
	tc.wg.Wait()
}
