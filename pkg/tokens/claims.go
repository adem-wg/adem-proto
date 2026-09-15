package tokens

import (
	"errors"
	"net/url"

	"github.com/fxamacker/cbor/v2"
)

type Claims struct {
	Ver    int      `cbor:"ver"`
	Iss    string   `cbor:"1,keyasint,omitempty"`
	Sub    string   `cbor:"2,keyasint,omitempty"`
	Exp    int64    `cbor:"4,keyasint"`
	Nbf    int64    `cbor:"5,keyasint"`
	Iat    int64    `cbor:"6,keyasint,omitempty"`
	Prp    byte     `cbor:"prp"`
	Assets []string `cbor:"assets,omitempty"`
	Key    []byte   `cbor:"key,omitempty"`
	End    *bool    `cbor:"end,omitempty"`
	Log    Log      `cbor:"log,omitempty"`
}

func (cs *Claims) GetEndorsedKID() (string, bool) {
	if cs.Key == nil {
		return "", false
	} else {
		return ThumbprintToString(cs.Key), true
	}
}

type Log = []*LogConfig

var ErrIllegalConst = errors.New("json element is illegal constant")

const RedCrProtective byte = 0b0000_0001
const RedCrIndicative byte = 0b0000_0010
const DangerousForces byte = 0b0000_0100
const CivilDefence byte = 0b0000_1000
const BlueShield byte = 0b0001_0000

const MaxPurpose = RedCrProtective | RedCrIndicative | DangerousForces | CivilDefence | BlueShield

// Struct that represents an identifying log binding.
type LogConfig struct {
	Id    []byte `cbor:"id"`
	Hash  []byte `cbor:"hash,omitempty"`
	Index *int64 `cbor:"index,omitempty"`
}

func DecodePayload(payload []byte) (*Claims, error) {
	var claims Claims
	if err := cbor.Unmarshal(payload, &claims); err != nil {
		return nil, err
	} else if claims.Ver != 1 {
		return nil, errors.New("illegal version")
	} else if err := validateOI(claims.Iss); err != nil {
		return nil, err
	} else if err := validateOI(claims.Sub); err != nil {
		return nil, err
	} else if claims.Prp <= 0 || MaxPurpose <= claims.Prp {
		return nil, errors.New("illegal purpose bitmask")
	} else {
		return &claims, nil
	}
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
	if url.Scheme != "https" || url.Host == "" || url.Opaque != "" || url.User != nil || url.Path != "" || url.RawQuery != "" || url.RawFragment != "" {
		return errors.New("illegal OI")
	}
	return nil
}
