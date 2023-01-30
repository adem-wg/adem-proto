package args

import (
	"errors"
	"os"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

var ErrEmptyPath = errors.New("no path provided")
var ErrNoAlg = errors.New("no algorithm given")
var ErrNoSuchAlg = errors.New("algorithm does not exist")

func loadKeys(path string, isPEM bool) (jwk.Set, error) {
	if path == "" {
		return nil, ErrEmptyPath
	} else if bs, err := os.ReadFile(path); err != nil {
		return nil, err
	} else if key, err := jwk.Parse(bs, jwk.WithPEM(isPEM)); err != nil {
		return nil, err
	} else {
		return key, nil
	}
}

func loadAlgByString(alg string) (*jwa.SignatureAlgorithm, error) {
	if alg == "" {
		return nil, ErrNoAlg
	}
	for _, a := range jwa.SignatureAlgorithms() {
		if a.String() == alg {
			return &a, nil
		}
	}
	return nil, ErrNoSuchAlg
}
