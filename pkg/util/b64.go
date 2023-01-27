package util

import "encoding/base64"

// B64Dec decodes a base64-encoded string (represented as byte array) into a
// byte array.
func B64Dec(src []byte) ([]byte, error) {
	dst := make([]byte, base64.StdEncoding.DecodedLen(len(src)))
	n, err := base64.StdEncoding.Decode(dst, src)
	if err != nil {
		return nil, err
	} else {
		return dst[:n], nil
	}
}
