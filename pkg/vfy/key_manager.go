package vfy

import (
	"context"
	"errors"
	"sync"

	"github.com/adem-wg/adem-proto/pkg/tokens"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
)

var ErrNoKeyFound = errors.New("no key found")

type keyManager struct {
	mu        sync.Mutex
	keys      map[string]jwk.Key
	listeners map[string][]chan jwk.Key
}

func NewKeyManager() *keyManager {
	var km keyManager
	km.keys = make(map[string]jwk.Key)
	km.listeners = make(map[string][]chan jwk.Key)
	return &km
}

func (km *keyManager) put(k jwk.Key) {
	km.mu.Lock()
	defer km.mu.Unlock()

	if k.KeyID() == "" {
		err := tokens.SetKID(k)
		if err != nil {
			return
		}
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

	c := make(chan jwk.Key)
	k, ok := km.keys[kid]
	if ok {
		c <- k
		close(c)
	} else {
		listeners, ok := km.listeners[kid]
		if ok {
			km.listeners[kid] = append(listeners, c)
		} else {
			km.listeners[kid] = [](chan jwk.Key){c}
		}
	}
	return c
}

func (km *keyManager) FetchKeys(ctx context.Context, sink jws.KeySink, sig *jws.Signature, m *jws.Message) error {
	jwk := sig.ProtectedHeaders().JWK()
	if jwk != nil {
		km.put(jwk)
	} else {
		kid := sig.ProtectedHeaders().KeyID()
		// TODO: next line might lead to non-termination
		jwk = <-km.get(kid)
	}

	if jwk == nil {
		return ErrNoKeyFound
	}

	// TODO: This is insecure because an attacker could set algorithm to none
	sink.Key(jwa.SignatureAlgorithm(sig.ProtectedHeaders().Algorithm()), jwk)
	return nil
}
