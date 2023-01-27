package tokens

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"

	"github.com/adem-wg/adem-proto/pkg/consts"
	"github.com/adem-wg/adem-proto/pkg/util"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// Register JWT fields of emblems for easier parsing.
func init() {
	jwt.RegisterCustomField("log", []*LogConfig{})
	jwt.RegisterCustomField("key", EmbeddedKey{})
}

// Struct that represents an identifying log binding.
type LogConfig struct {
	Ver  string   `json:"ver"`
	Id   string   `json:"id"`
	Hash LeafHash `json:"hash"`
}

// Wrapper type for easier JSON unmarshalling of base64-encoded JSON strings of
// leaf hashes.
type LeafHash struct {
	B64 string
	Raw []byte
}

// Attempt to parse a JSON value as string that contains a base64-encoded leaf
// hash.
func (h *LeafHash) UnmarshalJSON(bs []byte) (err error) {
	trimmed := bytes.Trim(bs, `"`)
	if raw, e := util.B64Dec(trimmed); e != nil {
		err = e
	} else {
		h.B64 = string(trimmed)
		h.Raw = raw
	}
	return
}

func (h *LeafHash) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`"%s"`, h.B64)), nil
}

// Wrapper type to parse "key" field as [jwk.Key].
type EmbeddedKey struct {
	Key jwk.Key
}

// Attempt to parse a JSON value as string that contains a single JWK in JSON
// encoding.
func (ek *EmbeddedKey) UnmarshalJSON(bs []byte) (err error) {
	trimmed := bytes.Trim(bs, `"`)
	if k, e := jwk.ParseKey(trimmed); e != nil {
		err = e
	} else {
		ek.Key = k
	}
	return
}

var ErrIllegalVersion = jwt.NewValidationError(errors.New("illegal version"))
var ErrIllegalPrp = jwt.NewValidationError(errors.New("illegal prp claim"))
var ErrIllegalDst = jwt.NewValidationError(errors.New("illegal dst claim"))
var ErrIllegalType = jwt.NewValidationError(errors.New("illegal claim type"))

// TODO: Validate ass/emb.ass claims
// TODO: Be more strict with type assertions

// Validation function for emblem tokens.
var EmblemValidator = jwt.ValidatorFunc(func(_ context.Context, t jwt.Token) jwt.ValidationError {
	if err := validateCommon(t); err != nil {
		return err
	}

	return nil
})

// Validation function for endorsement tokens.
var EndorsementValidator = jwt.ValidatorFunc(func(_ context.Context, t jwt.Token) jwt.ValidationError {
	if err := validateCommon(t); err != nil {
		return err
	}

	end, ok := t.Get("end")
	if ok {
		_, check := end.(bool)
		if !check {
			return ErrIllegalType
		}
	}

	return nil
})

// Validate that an OI has the form https://DOMAINNAME.
func validateOI(oi string) error {
	if oi == "" {
		return nil
	}

	url, err := url.Parse(oi)
	if err != nil {
		return errors.New("could not parse OI")
	}
	// TODO: verify that there is only one wildcard, and only in the leftmost label.
	if url.Scheme != "https" || url.Host == "" || url.Opaque != "" || url.User != nil || url.RawPath != "" || url.RawQuery != "" || url.RawFragment != "" {
		return errors.New("illegal OI")
	}
	return nil
}

// Validate claims shared by emblems and endorsements.
func validateCommon(t jwt.Token) jwt.ValidationError {
	if err := jwt.Validate(t); err != nil {
		return err.(jwt.ValidationError)
	}

	if ver, ok := t.Get(`ver`); !ok || ver.(string) != string(consts.V1) {
		return ErrIllegalVersion
	}

	if validateOI(t.Issuer()) != nil {
		return jwt.ErrInvalidIssuer()
	}

	if cnstrs, ok := t.Get(`emb`); ok {
		mcnstrs, ok := cnstrs.(map[string]interface{})
		if !ok {
			return ErrIllegalType
		}
		if err := validateConstraints(mcnstrs); err != nil {
			return err
		}
	}

	return nil
}

// Validate emblem constraints.
func validateConstraints(details map[string]interface{}) jwt.ValidationError {
	prps, ok := details["prp"]
	if ok {
		for _, prp := range prps.([]interface{}) {
			if prp.(string) != string(consts.Protective) && prp.(string) != string(consts.Indicative) {
				return ErrIllegalPrp
			}
		}
	}

	dsts, ok := details["dst"]
	if ok {
		for _, dst := range dsts.([]interface{}) {
			if dst.(string) != string(consts.DNS) && dst.(string) != string(consts.TLS) && dst.(string) != string(consts.UDP) {
				return ErrIllegalDst
			}
		}
	}

	return nil
}
