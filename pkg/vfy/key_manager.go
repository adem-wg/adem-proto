package vfy

import (
	"context"
	"errors"
	"log"
	"sync"

	"github.com/adem-wg/adem-proto/pkg/roots"
	"github.com/adem-wg/adem-proto/pkg/tokens"
	"github.com/adem-wg/adem-proto/pkg/util"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

var ErrNoKeyFound = errors.New("no key found")
var ErrRootKeyUnbound = errors.New("root key not properly committed")

type keyManager struct {
	lock      sync.Mutex
	init      sync.WaitGroup
	keys      map[string]jwk.Key
	listeners map[string][]util.Promise[jwk.Key]
}

func NewKeyManager(numThreads int) *keyManager {
	var km keyManager
	km.init.Add(numThreads)
	km.keys = make(map[string]jwk.Key)
	km.listeners = make(map[string][]util.Promise[jwk.Key])
	return &km
}

func (km *keyManager) waitForInit() {
	km.init.Wait()
}

func (km *keyManager) killListeners() {
	km.lock.Lock()
	defer km.lock.Unlock()

	for k, listeners := range km.listeners {
		for _, promise := range listeners {
			promise.Reject()
		}
		delete(km.listeners, k)
	}
}

func (km *keyManager) waiting() int {
	km.lock.Lock()
	defer km.lock.Unlock()

	sum := 0
	for _, listeners := range km.listeners {
		sum += len(listeners)
	}
	return sum
}

func (km *keyManager) put(k jwk.Key) bool {
	km.lock.Lock()
	defer km.lock.Unlock()

	if k.KeyID() == "" {
		err := tokens.SetKID(k)
		if err != nil {
			return false
		}
	}

	_, ok := km.keys[k.KeyID()]
	if ok {
		return false
	}

	km.keys[k.KeyID()] = k
	promises := km.listeners[k.KeyID()]
	if len(promises) == 0 {
		return false
	}

	for _, promise := range promises {
		if promise != nil {
			promise.Fulfill(k)
		}
	}
	delete(km.listeners, k.KeyID())
	return true
}

func (km *keyManager) get(kid string) util.Promise[jwk.Key] {
	km.lock.Lock()
	defer km.lock.Unlock()

	c := util.NewPromise[jwk.Key]()
	k, ok := km.keys[kid]
	if ok {
		c.Fulfill(k)
	} else {
		km.listeners[kid] = append(km.listeners[kid], c)
	}
	return c
}

func (km *keyManager) FetchKeys(ctx context.Context, sink jws.KeySink, sig *jws.Signature, m *jws.Message) error {
	var promise util.Promise[jwk.Key]
	var err error
	headerKey := sig.ProtectedHeaders().JWK()
	if t, e := jwt.Parse(m.Payload(), jwt.WithVerify(false)); e != nil {
		log.Printf("could not decode payload: %s", e)
		err = e
	} else if logs, ok := t.Get("log"); ok {
		for _, r := range roots.VerifyBindingCerts(t.Issuer(), headerKey, logs.([]*tokens.LogConfig)) {
			if !r.Ok {
				log.Printf("could not verify root key commitment for log ID %s", r.LogID)
				err = ErrRootKeyUnbound
				break
			}
		}
		if err == nil {
			promise = util.Resolve(headerKey)
		}
	} else if headerKID := sig.ProtectedHeaders().KeyID(); headerKID != "" {
		promise = km.get(headerKID)
	} else if headerKey.KeyID() != "" {
		promise = km.get(headerKey.KeyID())
	}

	km.init.Done()
	if err != nil {
		log.Printf("err: %s", err)
		return err
	}

	verificationKey := promise.Get()
	if verificationKey == nil {
		return ErrNoKeyFound
	}

	sink.Key(jwa.SignatureAlgorithm(verificationKey.KeyType()), verificationKey)
	return nil
}
