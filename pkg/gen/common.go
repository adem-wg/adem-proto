package gen

import (
	"crypto/rand"
	"time"

	"github.com/adem-wg/adem-proto/pkg/tokens"
	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

type TokenGenerator interface {
	SignToken() (*cose.Sign1Message, error)
}

type EmblemConfig struct {
	sk       *cose.Key
	proto    *tokens.Claims
	lifetime int64
}

func MkEmblemCfg(sk *cose.Key, proto *tokens.Claims, lifetime int64) *EmblemConfig {
	return &EmblemConfig{sk: sk, proto: proto, lifetime: lifetime}
}

type EndorsementConfig struct {
	EmblemConfig
	endorse []byte
}

func MkEndorsementCfg(sk *cose.Key, proto *tokens.Claims, endorse []byte, lifetime int64) *EndorsementConfig {
	return &EndorsementConfig{
		EmblemConfig: *MkEmblemCfg(sk, proto, lifetime),
		endorse:      endorse,
	}
}

func prepToken(t *tokens.Claims, lifetime int64) {
	t.Iat = time.Now().Unix()

	// Set nbf to iat if not already present
	if t.Nbf == 0 {
		t.Nbf = t.Iat
	}

	// Only set lifetime if not already present
	if t.Exp == 0 {
		t.Exp = t.Iat + lifetime
	}
}

func signWithHeaders(t *tokens.Claims, signingKey *cose.Key) (*cose.Sign1Message, error) {
	if signer, err := signingKey.Signer(); err != nil {
		return nil, err
	} else if kid, err := tokens.COSEThumbprint(signingKey); err != nil {
		return nil, err
	} else if payload, err := cbor.Marshal(t); err != nil {
		return nil, err
	} else {
		msg := cose.NewSign1Message()
		msg.Headers.Protected.SetAlgorithm(signingKey.Algorithm)
		msg.Headers.Protected[cose.HeaderLabelKeyID] = kid
		msg.Payload = payload
		if err := msg.Sign(rand.Reader, nil, signer); err != nil {
			return nil, err
		} else {
			return msg, nil
		}
	}
}
