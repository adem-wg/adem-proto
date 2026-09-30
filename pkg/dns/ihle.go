// Package dns implements the DNS distribution profile for ADEM.
package dns

import (
	"encoding/hex"
	"fmt"
	"strings"

	mdns "github.com/miekg/dns"
)

// Randomly chosen in the range 65280-65534
const TypeIHLE uint16 = 65297

func Token(rr mdns.RR) ([]byte, bool, error) {
	if rr.Header().Rrtype != TypeIHLE {
		return nil, false, nil
	}
	unknown, ok := rr.(*mdns.RFC3597)
	if !ok {
		return nil, true, fmt.Errorf("IHLE record has unexpected representation %T", rr)
	}
	token, err := hex.DecodeString(unknown.Rdata)
	if err != nil {
		return nil, true, err
	}
	return token, true, nil
}

// Lookup queries an arbitrary RR type and returns the IHLE RRset included in
// the response.  This exercises Additional-section processing rather than
// querying IHLE directly.
func Lookup(name, address string) ([][]byte, error) {
	request := new(mdns.Msg)
	request.SetQuestion(mdns.Fqdn(name), TypeIHLE)
	response, _, err := new(mdns.Client).Exchange(request, address)
	if err != nil {
		return nil, err
	}
	if response.Truncated {
		client := &mdns.Client{Net: "tcp"}
		response, _, err = client.Exchange(request, address)
		if err != nil {
			return nil, err
		}
	}
	if response.Rcode != mdns.RcodeSuccess {
		return nil, fmt.Errorf("DNS query failed: %s", mdns.RcodeToString[response.Rcode])
	}

	wantName := strings.ToLower(mdns.Fqdn(name))
	tokens := make([][]byte, 0)
	for _, rr := range append(response.Answer, response.Extra...) {
		if strings.ToLower(rr.Header().Name) != wantName || rr.Header().Class != mdns.ClassINET {
			continue
		} else if token, isIHLE, err := Token(rr); err != nil {
			return nil, err
		} else if isIHLE {
			tokens = append(tokens, token)
		}
	}
	return tokens, nil
}

// MatchesAsset applies the DNS profile's case-insensitive FQDN comparison.
func MatchesAsset(name string, assets []string) bool {
	want := mdns.Fqdn(name)
	for _, asset := range assets {
		if strings.EqualFold(want, mdns.Fqdn(asset)) {
			return true
		}
	}
	return false
}
