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
var ErrAlgsDiffer = errors.New("jws alg and verification key alg are different")

// A struct that implements the [jwt.KeyProvider] interface.
type keyManager struct {
	// Lock for map access
	lock sync.Mutex
	// Wait group that will be done once all verification threads obtained a
	// promise for their verification key.
	init sync.WaitGroup
	// Maps KIDs to keys. Only contains verified keys.
	keys map[string]jwk.Key
	// Promises waiting for keys.
	listeners map[string][]util.Promise[jwk.Key]
}

// Creates a new key manager to verify [numThreads]-many tokens asynchronously.
func NewKeyManager(numThreads int) *keyManager {
	var km keyManager
	km.init.Add(numThreads)
	km.keys = make(map[string]jwk.Key)
	km.listeners = make(map[string][]util.Promise[jwk.Key])
	return &km
}

// Wait until all verification threads obtained a promise for their verification
// key.
func (km *keyManager) waitForInit() {
	km.init.Wait()
}

// Cancel any further verification.
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

// How many blocked threads are there that wait for a key promise to be resolved?
func (km *keyManager) waiting() int {
	km.lock.Lock()
	defer km.lock.Unlock()

	sum := 0
	for _, listeners := range km.listeners {
		sum += len(listeners)
	}
	return sum
}

// Store a verified key and notify listeners waiting for that key.
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

// Get a key based on its [kid]. Returns a promise that may already be resolved.
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

// Implements the [jwt.KeyManager] interface. If the token includes a root key,
// the root key commitment will be verified, and when this succeeds, the root
// key will be used for verification. All other keys will register a listener
// and wait for their verification key to be verified externally.
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

	if verificationKey.Algorithm() != sig.ProtectedHeaders().Algorithm() {
		return ErrAlgsDiffer
	}

	sink.Key(jwa.SignatureAlgorithm(verificationKey.Algorithm().String()), verificationKey)
	return nil
}
