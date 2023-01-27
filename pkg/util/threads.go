package util

import (
	"sync"
)

type ThreadCount struct {
	lock  sync.Mutex
	wg    sync.WaitGroup
	count int
}

func NewThreadCount(numThreads int) *ThreadCount {
	tc := ThreadCount{count: numThreads}
	tc.wg.Add(numThreads)
	return &tc
}

func (tc *ThreadCount) Done() {
	tc.lock.Lock()
	defer tc.lock.Unlock()
	tc.wg.Done()
	tc.count -= 1
}

func (tc *ThreadCount) Running() int {
	tc.lock.Lock()
	defer tc.lock.Unlock()
	return tc.count
}

func (tc *ThreadCount) Wait() {
	tc.wg.Wait()
}
