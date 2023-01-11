package vfy

import (
	"sync"

	"github.com/lestrrat-go/jwx/v2/jwt"
)

type VerificationResult byte

var UNSIGNED VerificationResult = 0
var INVALID VerificationResult = 1
var SIGNED VerificationResult = 2
var ORGANIZATIONAL VerificationResult = 3
var ENDORSED VerificationResult = 4

func vfyTokenAsync(rawToken []byte, km *keyManager, results chan jwt.Token, wg *sync.WaitGroup) {
	defer wg.Done()

	token, err := jwt.Parse(rawToken, jwt.WithKeyProvider(km))
	if err != nil {
		return
	}
	results <- token
}

func VerifyTokens(rawTokens [][]byte) VerificationResult {
	var wg sync.WaitGroup
	wg.Add(len(rawTokens))
	km := NewKeyManager(len(rawTokens))
	results := make(chan jwt.Token)
	for _, rawToken := range rawTokens {
		go vfyTokenAsync(rawToken, km, results, &wg)
	}
	wg.Wait()
	close(results)
	return UNSIGNED
}
