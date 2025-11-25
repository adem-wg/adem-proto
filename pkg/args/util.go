package args

import (
	"errors"
	"os"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

var ErrEmptyPath = errors.New("no path provided")

func loadKeys(path string, isJWK bool) (jwk.Set, error) {
	if path == "" {
		return nil, ErrEmptyPath
	} else if bs, err := os.ReadFile(path); err != nil {
		return nil, err
	} else if key, err := jwk.Parse(bs, jwk.WithPEM(!isJWK)); err != nil {
		return nil, err
	} else {
		return key, nil
	}
}
