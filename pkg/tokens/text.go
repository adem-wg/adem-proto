package tokens

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
)

// Text is the DNS presentation format, also used for line-oriented CLI pipes.
func Text(raw []byte) string { return strings.ToUpper(hex.EncodeToString(raw)) }

func ParseText(line string) ([]byte, error) {
	raw, err := hex.DecodeString(strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, line))
	if err != nil {
		return nil, err
	}
	if err := ValidateRecord(raw); err != nil {
		return nil, err
	}
	return raw, nil
}

func ReadText(r io.Reader) ([][]byte, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 4096), 2*65535+1)
	var records [][]byte
	line := 0
	for scanner.Scan() {
		line++
		s := strings.TrimSpace(scanner.Text())
		if s == "" {
			continue
		}
		raw, err := ParseText(s)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		records = append(records, raw)
	}
	return records, scanner.Err()
}

// ValidateRecord accepts exactly one signed CWT or public COSE_Key data item.
func ValidateRecord(raw []byte) error {
	if _, err := DecodeMessage(raw); err == nil {
		return nil
	}
	if _, err := DecodePublicCOSEKey(raw); err == nil {
		return nil
	}
	return errors.New("record must contain one signed CWT or public COSE_Key without trailing data")
}
