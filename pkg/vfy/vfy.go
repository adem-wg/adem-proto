package vfy

import (
	"log"
	"sync"

	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type VerificationResult byte

var UNSIGNED VerificationResult = 0
var INVALID VerificationResult = 1
var SIGNED VerificationResult = 2
var ORGANIZATIONAL VerificationResult = 3
var ENDORSED VerificationResult = 4

type HeaderedTokens struct {
	Headers jws.Headers
	Token   jwt.Token
}

func vfyTokenAsync(rawToken []byte, km *keyManager, results chan HeaderedTokens, wg *sync.WaitGroup) {
	defer wg.Done()

	msg, err := jws.Parse(rawToken)
	if err != nil {
		return
	}
	token, err := jwt.Parse(rawToken, jwt.WithKeyProvider(km))
	if err != nil {
		return
	}
	results <- HeaderedTokens{msg.Signatures()[0].ProtectedHeaders(), token}
}

func VerifyTokens(rawTokens [][]byte) VerificationResult {
	var wg sync.WaitGroup
	wg.Add(len(rawTokens))
	km := NewKeyManager(len(rawTokens))
	results := make(chan HeaderedTokens)
	for _, rawToken := range rawTokens {
		go vfyTokenAsync(rawToken, km, results, &wg)
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	var emblem jwt.Token
	endorsements := []jwt.Token{}
	for htoken := range results {
		if htoken.Headers.Type() == "adem-emb" {
			if emblem != nil {
				// Multiple emblems
				log.Print("Token set contains multiple emblems")
				return INVALID
			}

			err := jwt.Validate(htoken.Token, jwt.WithValidator(EmblemValidator))
			if err != nil {
				log.Printf("Invalid emblem: %s", err)
				return INVALID
			}
			emblem = htoken.Token
		} else if htoken.Headers.Type() == "adem-end" {
			err := jwt.Validate(htoken.Token, jwt.WithValidator(EndorsementValidator))
			if err != nil {
				log.Printf("Invalid endorsement: %s", err)
			} else {
				endorsements = append(endorsements, htoken.Token)
			}
		} else {
			log.Printf("Token has wrong type: %s", htoken.Headers.Type())
		}
	}

	return SIGNED
}
