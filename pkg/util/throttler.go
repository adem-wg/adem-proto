package util

import (
	"math/big"
	"net"
	"time"
)

func ipToInt(addr *net.UDPAddr) int64 {
	return big.NewInt(0).SetBytes(addr.IP).Int64()
}

type timestamp struct {
	time int64
	val  int64
}

func (ts *timestamp) ToComparable() int64 {
	return ts.val
}

const SIZE int = 2 ^ 20

type ipThrottle struct {
	stored   Set[int64]
	queue    [SIZE]*timestamp
	queuePtr int
}

func MkThrottler() *ipThrottle {
	return &ipThrottle{stored: MkSet[int64]()}
}

func (t *ipThrottle) store(val int64) {
	ts := timestamp{time: time.Now().Unix(), val: val}
	if t.stored.Size() < SIZE {
		t.queue[t.stored.Size()] = &ts
	} else {
		t.stored.Rm(t.queue[t.queuePtr])
		t.queue[t.queuePtr] = &ts
		t.queuePtr = (t.queuePtr + 1) % SIZE
	}
	t.stored.Add(&ts)
}

func (t *ipThrottle) CanGo(addr *net.UDPAddr, timeout int64) bool {
	val := ipToInt(addr)
	defer t.store(val)

	el := t.stored.HasKey(val)
	if el == nil {
		return true
	}
	ts := el.(*timestamp)
	if ts == nil || ts.time+timeout < time.Now().Unix() {
		return true
	}
	return false
}
