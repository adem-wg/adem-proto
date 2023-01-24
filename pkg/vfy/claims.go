package vfy

import (
	"context"
	"errors"
	"net/url"

	"github.com/adem-wg/adem-proto/pkg/consts"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

var ErrIllegalVersion = jwt.NewValidationError(errors.New("illegal version"))
var ErrIllegalPrp = jwt.NewValidationError(errors.New("illegal prp claim"))
var ErrIllegalDst = jwt.NewValidationError(errors.New("illegal dst claim"))
var ErrIllegalType = jwt.NewValidationError(errors.New("illegal claim type"))

// TODO: Validate ass/emb.ass claims
// TODO: Be more strict with type assertions

var EmblemValidator = jwt.ValidatorFunc(func(_ context.Context, t jwt.Token) jwt.ValidationError {
	if err := validateCommon(t); err != nil {
		return err
	}

	return nil
})

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

func validateOI(oi string) error {
	if oi == "" {
		return nil
	}

	url, err := url.Parse(oi)
	if err != nil {
		return errors.New("could not parse OI")
	}
	if url.Scheme != "https" || url.Host == "" || url.Opaque != "" || url.User != nil || url.RawPath != "" || url.RawQuery != "" || url.RawFragment != "" {
		return errors.New("illegal OI")
	}
	return nil
}

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
