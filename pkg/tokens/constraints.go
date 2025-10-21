package tokens

import (
	"errors"

	"github.com/adem-wg/adem-proto/pkg/ident"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// Check that the given emblem's ass claim complies with the given ass
// constraints.
func checkAssetConstraint(emblem jwt.Token, constraints EmblemConstraints) bool {
	if len(constraints.Assets) == 0 {
		return true
	}

	ass, _ := emblem.Get("ass")
	for _, ai := range ass.([]*ident.AI) {
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

var ErrAssetConstraint = errors.New("emblem does not satisfy asset constraint")
var ErrPrpConstraint = errors.New("emblem does not satisfy prp constraint")
var ErrDstConstraint = errors.New("emblem does not satisfy dst constraint")
var ErrWndConstraint = errors.New("emblem does not satisfy wnd constraint")

// Verify that the given emblem complies with the given endorsement's
// constraints.
func VerifyConstraints(emblem jwt.Token, endorsement jwt.Token) error {
	if endCnstrs, ok := endorsement.Get("emb"); !ok {
		return nil
	} else if !checkAssetConstraint(emblem, endCnstrs.(EmblemConstraints)) {
		return ErrAssetConstraint
	} else if embCnstrs, ok := emblem.Get("emb"); !ok {
		return nil
	} else {
		embPrp := embCnstrs.(EmblemConstraints).Purpose
		endPrp := endCnstrs.(EmblemConstraints).Purpose
		if endPrp != nil && *endPrp&*embPrp != *embPrp {
			return ErrPrpConstraint
		}
		embDst := embCnstrs.(EmblemConstraints).Distribution
		endDst := endCnstrs.(EmblemConstraints).Distribution
		if endDst != nil && *endDst&*embDst != *embDst {
			return ErrDstConstraint
		}
		wnd := endCnstrs.(EmblemConstraints).Window
		if wnd != nil && emblem.Expiration().Unix()-emblem.NotBefore().Unix() > int64(*wnd) {
			return ErrWndConstraint
		}
	}
	return nil
}
