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
	timeout  int64
	stored   Set[int64]
	queue    [SIZE]*timestamp
	queuePtr int
}

// Returns a throttler that can memorize up to 2^20 IP addresses. Can be queried
// to check if an IP address was stored within the timeout window. If size is
// exceeded, the odlest IP address that was stored will be discarded first.
func MkThrottler(timeout int64) *ipThrottle {
	return &ipThrottle{timeout: timeout, stored: MkSet[int64]()}
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

// Check if an address was checked within timeout. Returns true if the IP
// address has not been stored, i.e., an expensive operation for that address
// can be performed. May result in false negatives if the throttler's capacity
// was exceeded, which is is 2^20.
func (t *ipThrottle) CanGo(addr *net.UDPAddr) bool {
	val := ipToInt(addr)
	defer t.store(val)

	el := t.stored.HasKey(val)
	if el == nil {
		return true
	}
	ts := el.(*timestamp)
	if ts == nil || ts.time+t.timeout < time.Now().Unix() {
		return true
	}
	return false
}
