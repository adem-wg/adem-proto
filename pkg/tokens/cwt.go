package tokens

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/adem-wg/adem-proto/pkg/consts"
	"github.com/adem-wg/adem-proto/pkg/ident"
	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

// Claims holds native CWT values: registered claims have integer labels and
// key thumbprints are byte strings. Log is protected COSE header metadata.
type Claims struct {
	cose.CWTClaims
	Log Log
}

func NewClaims() *Claims { return &Claims{CWTClaims: cose.CWTClaims{}} }

var claimLabels = map[string]int64{
	"iss": cose.CWTClaimIssuer, "sub": cose.CWTClaimSubject,
	"exp": cose.CWTClaimExpirationTime, "nbf": cose.CWTClaimNotBefore,
	"iat": cose.CWTClaimIssuedAt,
}

func (c *Claims) Issuer() (string, bool) {
	v, ok := c.CWTClaims[cose.CWTClaimIssuer].(string)
	return v, ok
}
func (c *Claims) Subject() (string, bool) {
	v, ok := c.CWTClaims[cose.CWTClaimSubject].(string)
	return v, ok
}

// Assets uses the existing asset identifier parser and matching semantics.
func (c *Claims) Assets() (Assets, error) {
	var values []string
	switch v := c.CWTClaims["assets"].(type) {
	case []string:
		values = v
	case []any:
		for _, value := range v {
			s, ok := value.(string)
			if !ok {
				return nil, ErrAssets
			}
			values = append(values, s)
		}
	default:
		return nil, ErrAssets
	}
	if len(values) == 0 {
		return nil, ErrAssets
	}
	assets := make(Assets, 0, len(values))
	for _, value := range values {
		ai, err := ident.ParseAI(value)
		if err != nil {
			return nil, err
		}
		assets = append(assets, ai)
	}
	return assets, nil
}

// NumericDate preserves fractional seconds and rejects non-finite or
// unrepresentable values before converting to Go time.
func NumericDate(value any) (time.Time, error) {
	switch n := value.(type) {
	case int64:
		return time.Unix(n, 0), nil
	case uint64:
		if n <= math.MaxInt64 {
			return time.Unix(int64(n), 0), nil
		}
	case float64:
		if !math.IsNaN(n) && !math.IsInf(n, 0) && n >= math.MinInt64 && n < math.MaxInt64 {
			seconds, fraction := math.Modf(n)
			return time.Unix(int64(seconds), int64(fraction*1e9)), nil
		}
	}
	return time.Time{}, errors.New("invalid NumericDate")
}

// ParseClaims reads an editable JSON prototype directly into native CWT values.
// JSON is a local input format only; it is never used to process a received CWT.
func ParseClaims(data []byte) (*Claims, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, err
	}
	if fields == nil {
		return nil, errors.New("prototype must be a JSON object")
	}
	c := NewClaims()
	for name, raw := range fields {
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return nil, fmt.Errorf("%s must not be null", name)
		}
		var value any
		switch name {
		case "log":
			if err := json.Unmarshal(raw, &c.Log); err != nil {
				return nil, err
			}
			continue
		case "key":
			var text string
			if err := json.Unmarshal(raw, &text); err != nil {
				return nil, err
			}
			key, err := KIDBytes(text)
			if err != nil {
				return nil, err
			}
			value = key
		case "ver", "prp":
			var n uint64
			if err := json.Unmarshal(raw, &n); err != nil {
				return nil, err
			}
			value = n
		case "iat", "nbf", "exp":
			var n json.Number
			if err := json.Unmarshal(raw, &n); err != nil {
				return nil, err
			}
			if len(raw) > 0 && raw[0] == '"' {
				return nil, errors.New("NumericDate must be a number")
			}
			if i, err := strconv.ParseInt(n.String(), 10, 64); err == nil {
				value = i
			} else if f, err := n.Float64(); err == nil {
				value = f
			} else {
				return nil, err
			}
			if _, err := NumericDate(value); err != nil {
				return nil, err
			}
		case "iss", "sub":
			var s string
			if err := json.Unmarshal(raw, &s); err != nil {
				return nil, err
			}
			value = s
		case "end":
			var b bool
			if err := json.Unmarshal(raw, &b); err != nil {
				return nil, err
			}
			value = b
		case "assets":
			var assets []string
			if err := json.Unmarshal(raw, &assets); err != nil {
				return nil, err
			}
			value = assets
		default:
			return nil, fmt.Errorf("unsupported claim %q", name)
		}
		if label, ok := claimLabels[name]; ok {
			c.CWTClaims[label] = value
		} else {
			c.CWTClaims[name] = value
		}
	}
	return c, nil
}

func ValidateClaims(c *Claims, endorsement bool) error {
	if c == nil || c.CWTClaims == nil {
		return errors.New("claims must be a map")
	}
	if ver, ok := c.CWTClaims["ver"].(uint64); !ok || ver != consts.V1 {
		return ErrIllegalVersion
	}
	if prp, ok := c.CWTClaims["prp"].(uint64); !ok || prp < 1 || prp > 31 {
		return ErrPrpConstraint
	}
	for _, label := range []int64{cose.CWTClaimNotBefore, cose.CWTClaimExpirationTime, cose.CWTClaimIssuedAt} {
		value, present := c.CWTClaims[label]
		if !present && label == cose.CWTClaimIssuedAt {
			continue
		}
		if _, err := NumericDate(value); err != nil {
			return fmt.Errorf("claim %d: %w", label, err)
		}
	}
	for _, label := range []int64{cose.CWTClaimIssuer, cose.CWTClaimSubject} {
		if value, present := c.CWTClaims[label]; present {
			s, ok := value.(string)
			if !ok || s == "" || validateOI(s) != nil {
				return errors.New("invalid organization identifier")
			}
		}
	}
	if _, present := c.CWTClaims["emb"]; present {
		return errors.New("obsolete emb claim")
	}
	_, assets := c.CWTClaims["assets"]
	_, key := c.CWTClaims["key"]
	_, end := c.CWTClaims["end"]
	if endorsement {
		if assets {
			return errors.New("assets claim only allowed on emblems")
		}
		if kid, ok := c.CWTClaims["key"].([]byte); !ok || len(kid) != 32 {
			return ErrNoEndorsedKey
		}
		if _, ok := c.CWTClaims["end"].(bool); !ok {
			return ErrEndMissing
		}
	} else {
		if key || end {
			return errors.New("endorsement claims on emblem")
		}
		if _, sub := c.CWTClaims[cose.CWTClaimSubject]; sub {
			return errors.New("sub claim only allowed on endorsements")
		}
		if c.Log != nil {
			return ErrLogClaim
		}
		if _, err := c.Assets(); err != nil {
			return err
		}
	}
	return nil
}

func (c *Claims) ValidateTime(now time.Time) error {
	nbf, err := NumericDate(c.CWTClaims[cose.CWTClaimNotBefore])
	if err != nil {
		return err
	}
	exp, err := NumericDate(c.CWTClaims[cose.CWTClaimExpirationTime])
	if err != nil {
		return err
	}
	if now.Before(nbf) {
		return errors.New("token is not yet valid")
	}
	if !now.Before(exp) {
		return errors.New("token has expired")
	}
	return nil
}

func EncodeClaims(c *Claims, endorsement bool) ([]byte, any, error) {
	if err := ValidateClaims(c, endorsement); err != nil {
		return nil, nil, err
	}
	for label := range c.CWTClaims {
		switch label {
		case cose.CWTClaimIssuer, cose.CWTClaimSubject, cose.CWTClaimExpirationTime, cose.CWTClaimNotBefore, cose.CWTClaimIssuedAt, "ver", "prp", "assets", "key", "end":
		default:
			return nil, nil, fmt.Errorf("unsupported claim %v", label)
		}
	}
	var logs any
	if c.Log != nil {
		entries, err := encodeLogs(c.Log)
		if err != nil {
			return nil, nil, err
		}
		logs = entries
	}
	payload, err := CBOR.Marshal(c.CWTClaims)
	return payload, logs, err
}

func decodeClaims(payload []byte, endorsement bool) (*Claims, error) {
	var fields map[any]cbor.RawMessage
	if err := strictCBOR.Unmarshal(payload, &fields); err != nil {
		return nil, err
	}
	if fields == nil {
		return nil, errors.New("claims must be a map")
	}
	c := NewClaims()
	for label, raw := range fields {
		switch k := label.(type) {
		case uint64:
			switch int64(k) {
			case cose.CWTClaimIssuer, cose.CWTClaimSubject, cose.CWTClaimExpirationTime, cose.CWTClaimNotBefore, cose.CWTClaimIssuedAt:
				label = int64(k)
			default:
				return nil, errors.New("forbidden registered CWT claim")
			}
		case string:
			if _, registered := claimLabels[k]; registered || k == "aud" || k == "cti" || k == "log" {
				return nil, errors.New("registered claims require integer labels; log belongs in protected header")
			}
		default:
			return nil, errors.New("unsupported claim label")
		}
		var value any
		if err := strictCBOR.Unmarshal(raw, &value); err != nil {
			return nil, err
		}
		c.CWTClaims[label] = value
	}
	if err := ValidateClaims(c, endorsement); err != nil {
		return nil, err
	}
	return c, nil
}

func DecodeClaims(m *cose.Sign1Message) (*Claims, bool, error) {
	if typ, present := m.Headers.Protected[int64(16)]; present && typ != consts.ADEMType {
		return nil, false, errors.New("invalid protected typ")
	}
	var fields map[any]cbor.RawMessage
	if err := strictCBOR.Unmarshal(m.Payload, &fields); err != nil {
		return nil, false, err
	}
	_, assets := fields["assets"]
	_, key := fields["key"]
	_, end := fields["end"]
	if assets && (key || end) || !assets && !(key && end) {
		return nil, false, errors.New("ambiguous or missing token kind")
	}
	endorsement := !assets
	c, err := decodeClaims(m.Payload, endorsement)
	if err != nil {
		return nil, false, err
	}
	if value, ok := m.Headers.Protected["log"]; ok {
		if !endorsement {
			return nil, false, ErrLogClaim
		}
		logs, err := decodeLogs(value)
		if err != nil {
			return nil, false, err
		}
		c.Log = logs
	}
	return c, endorsement, nil
}
