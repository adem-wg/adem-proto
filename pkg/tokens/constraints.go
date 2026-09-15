package tokens

import (
	"errors"
)

// Check that the given emblem's assets claim complies with the given assets
// constraints.
func checkAssetConstraint(emblem *Claims, constraints EmblemConstraints) bool {
	if constraints.Assets == nil {
		return true
	}

	assets, err := emblem.Assets()
	if err != nil {
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

// Verify the purpose bitmap authorized by an endorsement.
func VerifyConstraints(emblem *Claims, endorsement *Claims) error {
	emblemPurpose, embOK := emblem.CWTClaims["prp"].(uint64)
	endorsementPurpose, endOK := endorsement.CWTClaims["prp"].(uint64)
	if !embOK || !endOK || emblemPurpose < 1 || emblemPurpose > 31 || endorsementPurpose < 1 || endorsementPurpose > 31 || emblemPurpose&endorsementPurpose != emblemPurpose {
		return ErrPrpConstraint
	}
	return nil
}
