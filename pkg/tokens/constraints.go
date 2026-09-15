package tokens

import (
	"errors"
)

// Verify that the given emblem complies with the given endorsement's
// constraints.
func Valid(emblem *Claims, endorsement *Claims) error {
	embPrp := emblem.Prp
	endPrp := endorsement.Prp
	if endPrp&embPrp != embPrp {
		return errors.New("emblem does not satisfy prp constraint")
	} else {
		return nil
	}
}
