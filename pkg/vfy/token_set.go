package vfy

import (
	"bytes"
	"errors"
	"log"
	"sync"

	"github.com/adem-wg/adem-proto/pkg/tokens"
	"github.com/veraison/go-cose"
)

type TokenVerifier struct {
	Verify func() (*ADEMToken, error)
}

type TokenSet struct {
	lock         sync.Mutex
	keyMaterial  map[string]*cose.Key
	Endorsements []*ADEMToken
	Emblem       *ADEMToken
	Errors       []error
}

func NewTokenSet(keyMaterial tokens.KeySet) *TokenSet {
	var th TokenSet
	th.lock = sync.Mutex{}
	th.keyMaterial = keyMaterial
	th.Endorsements = make([]*ADEMToken, 0)
	th.Errors = make([]error, 0)
	return &th
}

func (th *TokenSet) AddToken(rawToken []byte) error {
	msg := cose.NewSign1Message()
	if err := msg.UnmarshalCBOR(bytes.Clone(rawToken)); err != nil {
		log.Printf("WARNING: discarding token - %v\n", err)
		return nil
	}

	if headerKid, ok := msg.Headers.Protected[cose.HeaderLabelKeyID]; !ok {
		log.Println("WARNING: discarding token - no kid in header")
		return nil
	} else if headerKidBs, ok := headerKid.([]byte); !ok {
		log.Printf("WARNING: discarding token - kid in header has type %T (need []byte)\n", headerKid)
		return nil
	} else {
		verificationKid := tokens.ThumbprintToString(headerKidBs)
		if verificationKey, ok := th.keyMaterial[verificationKid]; !ok {
			log.Printf("WARNING: discarding token - no verification key for %v\n", verificationKid)
			return nil
		} else if token, err := Verify(msg, verificationKid, verificationKey); err != nil {
			log.Printf("WARNING: discarding tokens - verification failed with error %v\n", err)
			return nil
		} else {
			th.lock.Lock()
			if token.IsEndorsement() {
				th.Endorsements = append(th.Endorsements, token)
			} else if token.IsEmblem() {
				if th.Emblem == nil {
					th.Emblem = token
				} else {
					return errors.New("multiple emblems found")
				}
			} else {
				log.Println("WARNING: discarding tokens - unrecognized token")
				return nil
			}
			th.lock.Unlock()
			return nil
		}
	}
}
