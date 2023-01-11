package vfy

import (
	"context"
	"errors"
	"sync"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
)

var NoKeyFound = errors.New("no key found")

type keyManager struct {
	mu        sync.Mutex
	providers *sync.WaitGroup
	keys      map[string]jwk.Key
	listeners map[string][]chan jwk.Key
}

func NewKeyManager(providersNum int) *keyManager {
	var km keyManager
	km.providers.Add(providersNum)
	km.keys = make(map[string]jwk.Key)
	km.listeners = make(map[string][]chan jwk.Key)

	go func() {
		// Wait until every token either stored a key or is waiting for a key...
		km.providers.Wait()

		for _, lstnrs := range km.listeners {
			if lstnrs == nil {
				continue
			}
			for _, lstnr := range lstnrs {
				if lstnr == nil {
					continue
				}
				// ...close any remaining channels because otherwise, we may not terminate
				close(lstnr)
			}
		}
	}()

	return &km
}

func (km *keyManager) put(k jwk.Key) {
	km.mu.Lock()
	defer km.mu.Unlock()
	defer km.providers.Done()

	if k.KeyID() == "" {
		return
	}

	_, ok := km.keys[k.KeyID()]
	if ok {
		return
	}

	km.keys[k.KeyID()] = k
	lstnrs, ok := km.listeners[k.KeyID()]
	if lstnrs == nil || !ok {
		return
	}

	for _, lstnr := range lstnrs {
		if lstnr != nil {
			lstnr <- k
			close(lstnr)
		}
	}
}

func (km *keyManager) get(kid string) chan jwk.Key {
	km.mu.Lock()
	defer km.mu.Unlock()
	km.providers.Done()

	c := make(chan jwk.Key)
	k, ok := km.keys[kid]
	if ok {
		c <- k
		close(c)
	}
	return c
}

func (km *keyManager) FetchKeys(ctx context.Context, sink jws.KeySink, sig *jws.Signature, m *jws.Message) error {
	jwk := sig.ProtectedHeaders().JWK()
	if jwk != nil {
		km.put(jwk)
	} else {
		kid := sig.ProtectedHeaders().KeyID()
		jwk = <-km.get(kid)
	}

	if jwk == nil {
		return NoKeyFound
	}

	sink.Key(jwa.SignatureAlgorithm(jwk.Algorithm().String()), jwk)
	return nil
}
