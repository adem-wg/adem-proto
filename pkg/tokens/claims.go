package tokens

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/url"

	"github.com/adem-wg/adem-proto/pkg/consts"
	"github.com/adem-wg/adem-proto/pkg/ident"
	"github.com/adem-wg/adem-proto/pkg/util"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

type Log = []*LogConfig
type Assets = []*ident.AI

// Register JWT fields of emblems for easier parsing.
func init() {
	jwt.RegisterCustomField("log", Log{})
	jwt.RegisterCustomField("key", "")
	jwt.RegisterCustomField("assets", Assets{})
	jwt.RegisterCustomField("emb", EmblemConstraints{})
	jwt.RegisterCustomField("ver", "")
}

var ErrIllegalConst = errors.New("json element is illegal constant")

type PurposeMask byte

const Protective PurposeMask = 0b0000_0001
const Indicative PurposeMask = 0b0000_0010

func (pm *PurposeMask) UnmarshalJSON(in []byte) error {
	var prps []string
	var mask PurposeMask
	if err := json.Unmarshal(in, &prps); err != nil {
		return err
	} else {
		for _, prp := range prps {
			switch prp {
			case consts.Protective:
				mask |= Protective
			case consts.Indicative:
				mask |= Indicative
			default:
				return ErrIllegalConst
			}
		}
	}
	*pm = mask
	return nil
}

func (pm *PurposeMask) MarshalJSON() ([]byte, error) {
	var purposes []string
	if *pm&Protective != 0 {
		purposes = append(purposes, consts.Protective)
	}
	if *pm&Indicative != 0 {
		purposes = append(purposes, consts.Indicative)
	}
	return json.Marshal(purposes)
}

type ChannelMask byte

const DNS ChannelMask = 0b0000_0001
const TLS ChannelMask = 0b0000_0010
const UDP ChannelMask = 0b0000_0100

func (cm *ChannelMask) UnmarshalJSON(bs []byte) error {
	var dsts []string
	var mask ChannelMask
	if err := json.Unmarshal(bs, &dsts); err != nil {
		return err
	} else {
		for _, dst := range dsts {
			switch dst {
			case consts.DNS:
				mask |= DNS
			case consts.TLS:
				mask |= TLS
			case consts.UDP:
				mask |= UDP
			default:
				return ErrIllegalConst
			}
		}
	}
	*cm = mask
	return nil
}

func (cm *ChannelMask) MarshalJSON() ([]byte, error) {
	var dsts []string
	if *cm&DNS != 0 {
		dsts = append(dsts, consts.DNS)
	}
	if *cm&TLS != 0 {
		dsts = append(dsts, consts.TLS)
	}
	if *cm&UDP != 0 {
		dsts = append(dsts, consts.UDP)
	}
	return json.Marshal(dsts)
}

type EmblemConstraints struct {
	Purpose      *PurposeMask `json:"prp,omitempty"`
	Distribution *ChannelMask `json:"dst,omitempty"`
	Assets       []*ident.AI  `json:"assets,omitempty"`
	Window       *int         `json:"wnd,omitempty"`
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
	return json.Marshal(h.B64)
}

var ErrIllegalVersion = errors.New("illegal version")
var ErrIllegalType = errors.New("illegal claim type")
var ErrAssets = errors.New("emblems require non-empty assets claim")
var ErrLogClaim = errors.New("emblems must not contain a log claim")
var ErrEndMissing = errors.New("endorsements require end claim")

// Validation function for emblem tokens.
var EmblemValidator = jwt.ValidatorFunc(func(_ context.Context, t jwt.Token) error {
	if err := validateCommon(t); err != nil {
		return err
	}

	var assets Assets
	if err := t.Get("assets", &assets); err != nil {
		return ErrAssets
	} else if len(assets) == 0 {
		return ErrAssets
	}

	if t.Has("log") {
		return ErrLogClaim
	}

	return nil
})

// Validation function for endorsement tokens.
var EndorsementValidator = jwt.ValidatorFunc(func(_ context.Context, t jwt.Token) error {
	if err := validateCommon(t); err != nil {
		return err
	}

	var end bool
	err := t.Get("end", &end)
	if err == nil {
		if !end {
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
	if url.Scheme != "https" || url.Host == "" || url.Opaque != "" || url.User != nil || url.Path != "" || url.RawQuery != "" || url.RawFragment != "" {
		return errors.New("illegal OI")
	}
	return nil
}

// Validate claims shared by emblems and endorsements.
func validateCommon(t jwt.Token) error {
	if err := jwt.Validate(t); err != nil {
		return err
	}

	var ver string
	if err := t.Get("ver", &ver); err != nil || ver != string(consts.V1) {
		return ErrIllegalVersion
	}

	if iss, ok := t.Issuer(); ok && validateOI(iss) != nil {
		return jwt.InvalidIssuerError()
	}

	return nil
}
