package vfy

import (
	"context"
	"errors"
	"log"
	"sync"

	"github.com/adem-wg/adem-proto/pkg/roots"
	"github.com/adem-wg/adem-proto/pkg/tokens"
	"github.com/adem-wg/adem-proto/pkg/util"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

var ErrNoKeyFound = errors.New("no key found")
var ErrRootKeyUnbound = errors.New("root key not properly committed")
var ErrAlgsDiffer = errors.New("jws alg and verification key alg are different")
var ErrUnexpectedAlg = errors.New("could not find verification algorithm")
var ErrLogsEmpty = errors.New("logs field cannot be empty")
var ErrNoIss = errors.New("issuer claim missing")

// A struct that implements the [jwt.KeyProvider] interface.
type keyManager struct {
	// Lock for map access
	lock sync.Mutex
	// Wait group that will be done once all verification threads obtained a
	// promise for their verification key.
	init sync.WaitGroup
	// Maps KIDs to keys. Only contains verified keys.
	keys         map[string]jwk.Key
	keysVerified map[string]bool
	// Promises waiting for keys.
	listeners map[string][]util.Promise[jwk.Key]
}

// Creates a new key manager to verify [numThreads]-many tokens asynchronously.
func NewKeyManager(untrustedKeys []jwk.Key, numThreads int) *keyManager {
	var km keyManager
	km.init.Add(numThreads)
	km.keys = make(map[string]jwk.Key)
	for _, k := range untrustedKeys {
		if kid, err := tokens.GetKID(k); err == nil {
			km.keys[kid] = k
		}
	}

	km.keysVerified = make(map[string]bool)
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

func (km *keyManager) setVerified(kid string) bool {
	km.lock.Lock()
	defer km.lock.Unlock()

	if _, ok := km.keys[kid]; !ok {
		return false
	} else if verified, ok := km.keysVerified[kid]; ok && verified {
		return false
	} else {
		km.keysVerified[kid] = true
		return km.resolve(kid)
	}
}

// Store a verified key and notify listeners waiting for that key.
func (km *keyManager) put(k jwk.Key) bool {
	km.lock.Lock()
	defer km.lock.Unlock()

	kid, err := tokens.GetKID(k)
	if err != nil {
		return false
	} else if fp, err := tokens.CalcKID(k); err != nil {
		// We set and calculate the KID ID to be consistent with key hashing later
		// down the line.
		return false
	} else if err := k.Set("kid", fp); err != nil {
		return false
	}

	_, ok1 := km.keys[kid]
	verified, ok2 := km.keysVerified[kid]
	if ok1 && verified && ok2 {
		return false
	}

	km.keys[kid] = k
	km.keysVerified[kid] = true
	return km.resolve(kid)
}

// Resolve all promises associated with a key id. For internal use only. The
// function assumes that (a) it is not called concurrently, (b) there is a key
// for the kid, (c) the key has been verified.
func (km *keyManager) resolve(kid string) bool {
	promises := km.listeners[kid]
	if len(promises) == 0 {
		return false
	}

	for _, promise := range promises {
		if promise != nil {
			promise.Fulfill(km.keys[kid])
		}
	}
	delete(km.listeners, kid)
	return true
}

// Get a key based on its [kid]. Returns a promise that may already be resolved.
func (km *keyManager) get(kid string) util.Promise[jwk.Key] {
	km.lock.Lock()
	defer km.lock.Unlock()

	c := util.NewPromise[jwk.Key]()
	k, ok := km.keys[kid]
	verified, ok2 := km.keysVerified[kid]
	if ok && verified && ok2 {
		c.Fulfill(k)
	} else {
		km.listeners[kid] = append(km.listeners[kid], c)
	}
	return c
}

func (km *keyManager) getVerificationKey(sig *jws.Signature) util.Promise[jwk.Key] {
	if headerKid, ok := sig.ProtectedHeaders().KeyID(); ok {
		return km.get(headerKid)
	} else if headerKey, ok := sig.ProtectedHeaders().JWK(); !ok {
		return util.Rejected[jwk.Key]()
	} else if headerKeyKid, ok := headerKey.KeyID(); !ok {
		return util.Rejected[jwk.Key]()
	} else {
		return km.get(headerKeyKid)
	}
}

// Implements the [jwt.KeyManager] interface. If the token includes a root key,
// the root key commitment will be verified, and when this succeeds, the root
// key will be used for verification. All other keys will register a listener
// and wait for their verification key to be verified externally.
func (km *keyManager) FetchKeys(ctx context.Context, sink jws.KeySink, sig *jws.Signature, m *jws.Message) error {
	var promise util.Promise[jwk.Key]
	var err error
	var logs tokens.Log
	if t, e := jwt.Parse(m.Payload(), jwt.WithVerify(false)); e != nil {
		log.Printf("could not decode payload: %s", e)
		err = e
	} else if logFetchErr := t.Get("log", &logs); logFetchErr == nil {
		headerKey, hasHeaderKey := sig.ProtectedHeaders().JWK()
		headerKid, hasHeaderKeyID := sig.ProtectedHeaders().KeyID()
		headerKidKey, haveKey := km.keys[headerKid]
		if len(logs) == 0 {
			err = ErrLogsEmpty
		} else if !hasHeaderKey && !(hasHeaderKeyID && haveKey) {
			err = ErrNoKeyFound
		} else if iss, ok := t.Issuer(); !ok {
			err = ErrNoIss
		} else {
			var checkKey jwk.Key
			if hasHeaderKey {
				checkKey = headerKey
			} else {
				// This is the only case where we access the key map without checking
				// for keys to have been verified.
				checkKey = headerKidKey
			}

			for _, r := range roots.VerifyBindingCerts(iss, checkKey, logs) {
				if !r.Ok {
					log.Printf("could not verify root key commitment for log ID %s", r.LogID)
					err = ErrRootKeyUnbound
					break
				}
			}

			if err == nil {
				km.put(checkKey)
			}
		}
	} else if !errors.Is(logFetchErr, jwt.ClaimNotFoundError()) {
		return logFetchErr
	}

	promise = km.getVerificationKey(sig)
	km.init.Done()
	if err != nil {
		log.Printf("err: %s", err)
		return err
	}

	verificationKey := promise.Get()
	if verificationKey == nil {
		return ErrNoKeyFound
	}

	if verifAlg, ok := verificationKey.Algorithm(); !ok {
		return ErrAlgsDiffer
	} else if sigAlg, ok := sig.ProtectedHeaders().Algorithm(); !ok {
		return ErrAlgsDiffer
	} else if verifAlg != sigAlg {
		return ErrAlgsDiffer
	} else if alg, ok := jwa.LookupSignatureAlgorithm(verifAlg.String()); !ok {
		return ErrUnexpectedAlg
	} else {
		sink.Key(alg, verificationKey)
	}

	return nil
}
