package tokens

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"strings"

	"github.com/adem-wg/adem-proto/pkg/consts"
	"github.com/adem-wg/adem-proto/pkg/ident"
	"github.com/adem-wg/adem-proto/pkg/util"
)

type Log = []*LogConfig
type Assets = []*ident.AI

var ErrIllegalConst = errors.New("json element is illegal constant")

type PurposeMask byte

const Protective PurposeMask = 0b0000_0001
const Indicative PurposeMask = 0b0000_0010
const DangerousForces PurposeMask = 4
const CivilDefense PurposeMask = 8
const BlueShield PurposeMask = 16

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
			case "dangerous-forces":
				mask |= DangerousForces
			case "civil-defense":
				mask |= CivilDefense
			case "blue-shield":
				mask |= BlueShield
			default:
				return ErrIllegalConst
			}
		}
	}
	*pm = mask
	return nil
}

func (pm *PurposeMask) MarshalJSON() ([]byte, error) {
	purposes := []string{}
	if *pm&Protective != 0 {
		purposes = append(purposes, consts.Protective)
	}
	if *pm&Indicative != 0 {
		purposes = append(purposes, consts.Indicative)
	}
	if *pm&DangerousForces != 0 {
		purposes = append(purposes, "dangerous-forces")
	}
	if *pm&CivilDefense != 0 {
		purposes = append(purposes, "civil-defense")
	}
	if *pm&BlueShield != 0 {
		purposes = append(purposes, "blue-shield")
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
			default:
				return ErrIllegalConst
			}
		}
	}
	*cm = mask
	return nil
}

func (cm *ChannelMask) MarshalJSON() ([]byte, error) {
	dsts := []string{}
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

func (c *EmblemConstraints) UnmarshalJSON(raw []byte) error {
	type plain EmblemConstraints
	var decoded plain
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}
	*c = EmblemConstraints(decoded)
	return nil
}

// MarshalJSON preserves an explicitly empty asset constraint, which permits
// no assets and is different from an absent (unrestricted) constraint.
func (c EmblemConstraints) MarshalJSON() ([]byte, error) {
	fields := map[string]any{}
	if c.Purpose != nil {
		fields["prp"] = c.Purpose
	}
	if c.Distribution != nil {
		fields["dst"] = c.Distribution
	}
	if c.Assets != nil {
		fields["assets"] = c.Assets
	}
	if c.Window != nil {
		fields["wnd"] = c.Window
	}
	return json.Marshal(fields)
}

// Struct that represents an identifying log binding.
type LogConfig struct {
	Id    string    `json:"id"`
	Hash  *LeafHash `json:"hash,omitempty"`
	Index *uint64   `json:"index,omitempty"`
}

// Reject obsolete log fields instead of silently producing different metadata.
func (cfg *LogConfig) UnmarshalJSON(raw []byte) error {
	type plain LogConfig
	var decoded plain
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}
	*cfg = LogConfig(decoded)
	return cfg.Validate()
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
var ErrAssets = errors.New("emblems require non-empty assets claim")
var ErrLogClaim = errors.New("emblems must not contain a log claim")
var ErrEndMissing = errors.New("endorsements require end claim")

// Validate that an OI has the form https://DOMAINNAME.
func validateOI(oi string) error {
	if oi == "" {
		return nil
	}

	url, err := url.Parse(oi)
	if err != nil {
		return errors.New("could not parse OI")
	}
	if url.Scheme != "https" || url.Host == "" || url.Host != strings.ToLower(url.Host) || url.Port() != "" || url.Opaque != "" || url.User != nil || url.Path != "" || url.RawQuery != "" || url.RawFragment != "" || url.Fragment != "" || oi != "https://"+url.Host || net.ParseIP(url.Hostname()) != nil {
		return errors.New("illegal OI")
	}
	host := strings.TrimSuffix(url.Host, ".")
	if len(host) > 253 {
		return errors.New("illegal OI hostname")
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("illegal OI hostname")
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return errors.New("illegal OI hostname")
			}
		}
	}
	return nil
}
