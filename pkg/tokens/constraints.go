package tokens

import (
	"errors"

	"github.com/lestrrat-go/jwx/v3/jwt"
)

// Check that the given emblem's assets claim complies with the given assets
// constraints.
func checkAssetConstraint(emblem jwt.Token, constraints EmblemConstraints) bool {
	if len(constraints.Assets) == 0 {
		return true
	}

	var assets Assets
	if err := emblem.Get("assets", &assets); err != nil {
		return false
	} else {
		for _, ai := range assets {
			match := false
			for _, constraint := range constraints.Assets {
				if constraint.MoreGeneral(ai) {
					match = true
					break
				}
			}
			if !match {
				return false
			}
		}
		return true
	}
}

var ErrAssetConstraint = errors.New("emblem does not satisfy asset constraint")
var ErrPrpConstraint = errors.New("emblem does not satisfy prp constraint")
var ErrDstConstraint = errors.New("emblem does not satisfy dst constraint")
var ErrWndConstraint = errors.New("emblem does not satisfy wnd constraint")
var ErrMissingExpNbf = errors.New("emblem misses nbf or exp")

// Verify that the given emblem complies with the given endorsement's
// constraints.
func VerifyConstraints(emblem jwt.Token, endorsement jwt.Token) error {
	var endCnstrs, embCnstrs EmblemConstraints
	if err := endorsement.Get("emb", &endCnstrs); err != nil {
		if errors.Is(err, jwt.ClaimNotFoundError()) {
			return nil
		} else {
			return err
		}
	} else if !checkAssetConstraint(emblem, endCnstrs) {
		return ErrAssetConstraint
	} else if err := emblem.Get("emb", &embCnstrs); err != nil {
		return err // this claim must be present; any error should lead to failure
	} else {
		embPrp := embCnstrs.Purpose
		endPrp := endCnstrs.Purpose
		if endPrp != nil && *endPrp&*embPrp != *embPrp {
			return ErrPrpConstraint
		}
		embDst := embCnstrs.Distribution
		endDst := endCnstrs.Distribution
		if endDst != nil && *endDst&*embDst != *embDst {
			return ErrDstConstraint
		}
		wnd := endCnstrs.Window
		if exp, ok := emblem.Expiration(); !ok {
			return ErrMissingExpNbf
		} else if nbf, ok := emblem.NotBefore(); !ok {
			return ErrMissingExpNbf
		} else if wnd != nil && exp.Unix()-nbf.Unix() > int64(*wnd) {
			return ErrWndConstraint
		}
	}
	return nil
}
