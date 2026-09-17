// Package dns implements the DNS distribution profile for ADEM.
package dns

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/adem-wg/adem-proto/pkg/tokens"
	mdns "github.com/miekg/dns"
	"github.com/veraison/go-cose"
)

// TypeIHLE is a provisional private-use RR type.  The specification has not
// yet received an IANA-assigned type value.
const TypeIHLE uint16 = 65400

func ValidateToken(token []byte) error {
	message := cose.NewSign1Message()
	if err := message.UnmarshalCBOR(token); err == nil {
		if _, err := tokens.DecodePayload(message.Payload); err != nil {
			return fmt.Errorf("invalid ADEM CWT: %w", err)
		}
		return nil
	}
	if _, err := tokens.ParseKey(token); err == nil {
		return nil
	}
	return errors.New("IHLE token is neither an ADEM CWT nor a COSE_Key")
}

func NewIHLE(name string, ttl uint32, token []byte) (*mdns.RFC3597, error) {
	if err := ValidateToken(token); err != nil {
		return nil, err
	}
	return &mdns.RFC3597{
		Hdr: mdns.RR_Header{
			Name:   mdns.Fqdn(name),
			Rrtype: TypeIHLE,
			Class:  mdns.ClassINET,
			Ttl:    ttl,
		},
		Rdata: hex.EncodeToString(token),
	}, nil
}

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
	if err := ValidateToken(token); err != nil {
		return nil, true, err
	}
	return token, true, nil
}

// Lookup queries an arbitrary RR type and returns the IHLE RRset included in
// the response.  This exercises Additional-section processing rather than
// querying IHLE directly.
func Lookup(name, address string) ([][]byte, error) {
	request := new(mdns.Msg)
	request.SetQuestion(mdns.Fqdn(name), mdns.TypeA)
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
		}
		token, isIHLE, err := Token(rr)
		if err != nil {
			return nil, err
		}
		if isIHLE {
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

type Handler struct {
	name  string
	rrset []mdns.RR
}

func NewHandler(name string, ttl uint32, tokens [][]byte) (*Handler, error) {
	rrset := make([]mdns.RR, 0, len(tokens))
	for _, token := range tokens {
		rr, err := NewIHLE(name, ttl, token)
		if err != nil {
			return nil, err
		}
		rrset = append(rrset, rr)
	}
	return &Handler{name: strings.ToLower(mdns.Fqdn(name)), rrset: rrset}, nil
}

func cloneRRSet(rrset []mdns.RR) []mdns.RR {
	cloned := make([]mdns.RR, len(rrset))
	for i, rr := range rrset {
		cloned[i] = mdns.Copy(rr)
	}
	return cloned
}

func responseLimit(request *mdns.Msg, writer mdns.ResponseWriter) int {
	if _, ok := writer.RemoteAddr().(*net.TCPAddr); ok {
		return mdns.MaxMsgSize
	}
	if option := request.IsEdns0(); option != nil && option.UDPSize() > mdns.MinMsgSize {
		return int(option.UDPSize())
	}
	return mdns.MinMsgSize
}

func (h *Handler) ServeDNS(writer mdns.ResponseWriter, request *mdns.Msg) {
	response := new(mdns.Msg)
	response.SetReply(request)
	response.Authoritative = true

	if len(request.Question) != 1 || strings.ToLower(request.Question[0].Name) != h.name {
		response.Rcode = mdns.RcodeNameError
	} else {
		question := request.Question[0]
		if question.Qclass == mdns.ClassINET {
			if question.Qtype == TypeIHLE || question.Qtype == mdns.TypeANY {
				response.Answer = cloneRRSet(h.rrset)
			} else {
				response.Extra = cloneRRSet(h.rrset)
			}
		}
	}

	limit := responseLimit(request, writer)
	if response.Len() > limit {
		response.Truncated = true
		response.Answer = nil
		response.Extra = nil
	}
	_ = writer.WriteMsg(response)
}
