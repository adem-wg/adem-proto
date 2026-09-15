// Package discovery implements the draft IHLE wire format and a local test DNS server.
package discovery

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/adem-wg/adem-proto/pkg/tokens"
	"github.com/miekg/dns"
)

// DefaultType is a private-use RR type until IANA assigns IHLE a value.
const DefaultType uint16 = 65400

// Handler is a single-owner authoritative test zone. It does not recurse.
type Handler struct {
	Name    string
	Class   uint16
	Type    uint16
	TTL     uint32
	Records [][]byte
	Address net.IP
}

func NewHandler(name string, class, rrtype uint16, ttl uint32, records [][]byte, address net.IP) (*Handler, error) {
	name = dns.Fqdn(name)
	if _, ok := dns.IsDomainName(name); !ok {
		return nil, errors.New("invalid owner name")
	}
	if len(records) == 0 {
		return nil, errors.New("at least one IHLE record is required")
	}
	h := &Handler{Name: name, Class: class, Type: rrtype, TTL: ttl, Address: address}
	for _, raw := range records {
		if len(raw) > 65535 {
			return nil, errors.New("IHLE RDATA exceeds RDLENGTH")
		}
		if err := tokens.ValidateRecord(raw); err != nil {
			return nil, err
		}
		h.Records = append(h.Records, append([]byte(nil), raw...))
	}
	// Fail at configuration time if even TCP cannot carry the complete RRset.
	q := new(dns.Msg)
	q.SetQuestion(name, rrtype)
	q.Question[0].Qclass = class
	m := h.response(q)
	if b, err := m.Pack(); err != nil || len(b) > dns.MaxMsgSize {
		return nil, errors.New("complete RRset exceeds DNS TCP message size")
	}
	return h, nil
}

func (h *Handler) response(q *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(q)
	if len(q.Question) != 1 || q.Opcode != dns.OpcodeQuery {
		m.Rcode = dns.RcodeFormatError
		return m
	}
	question := q.Question[0]
	if !strings.EqualFold(question.Name, h.Name) || question.Qclass != h.Class {
		m.Rcode = dns.RcodeRefused
		return m
	}
	m.Authoritative = true
	records := make([]dns.RR, 0, len(h.Records))
	for _, raw := range h.Records {
		records = append(records, &dns.RFC3597{Hdr: dns.RR_Header{Name: h.Name, Rrtype: h.Type, Class: h.Class, Ttl: h.TTL}, Rdata: tokens.Text(raw)})
	}
	if question.Qtype == h.Type || question.Qtype == dns.TypeANY {
		m.Answer = records
	} else {
		m.Extra = records
	}
	if h.Address != nil {
		if (question.Qtype == dns.TypeA || question.Qtype == dns.TypeANY) && h.Address.To4() != nil {
			m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: h.Name, Rrtype: dns.TypeA, Class: h.Class, Ttl: h.TTL}, A: h.Address.To4()})
		} else if (question.Qtype == dns.TypeAAAA || question.Qtype == dns.TypeANY) && h.Address.To4() == nil {
			m.Answer = append(m.Answer, &dns.AAAA{Hdr: dns.RR_Header{Name: h.Name, Rrtype: dns.TypeAAAA, Class: h.Class, Ttl: h.TTL}, AAAA: h.Address})
		}
	}
	return m
}

func (h *Handler) ServeDNS(w dns.ResponseWriter, q *dns.Msg) {
	m := h.response(q)
	if _, udp := w.RemoteAddr().(*net.UDPAddr); udp {
		limit := 512
		if opt := q.IsEdns0(); opt != nil {
			limit = max(512, min(int(opt.UDPSize()), 1232))
			m.SetEdns0(uint16(limit), false)
		}
		if b, err := m.Pack(); err != nil || len(b) > limit {
			// Never expose a partial IHLE RRset. The TCP response contains every item.
			m.Truncated = true
			m.Answer = withoutType(m.Answer, h.Type)
			m.Extra = withoutType(m.Extra, h.Type)
		}
	}
	_ = w.WriteMsg(m)
}

func withoutType(rrs []dns.RR, t uint16) []dns.RR {
	out := make([]dns.RR, 0, len(rrs))
	for _, rr := range rrs {
		if rr.Header().Rrtype != t {
			out = append(out, rr)
		}
	}
	return out
}

// Probe queries either IHLE directly or an ordinary QTYPE and collects IHLE
// from Answer and Additional. A truncated UDP answer is retried over TCP.
func Probe(name, server string, qtype, rrtype uint16) ([][]byte, error) {
	if server == "" {
		cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil {
			return nil, err
		}
		if len(cfg.Servers) == 0 {
			return nil, errors.New("no DNS server configured")
		}
		server = net.JoinHostPort(cfg.Servers[0], cfg.Port)
	}
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), qtype)
	q.SetEdns0(1232, false)
	cl := &dns.Client{Net: "udp", Timeout: 5 * time.Second}
	m, _, err := cl.Exchange(q, server)
	if err != nil {
		return nil, err
	}
	if m.Truncated {
		cl.Net = "tcp"
		m, _, err = cl.Exchange(q, server)
		if err != nil {
			return nil, err
		}
	}
	if m.Truncated {
		return nil, errors.New("truncated TCP response")
	}
	if m.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("DNS response: %s", dns.RcodeToString[m.Rcode])
	}
	if len(m.Question) != 1 || m.Question[0] != q.Question[0] {
		return nil, errors.New("DNS question mismatch")
	}
	var records [][]byte
	for _, rr := range append(m.Answer, m.Extra...) {
		if rr.Header().Rrtype != rrtype || rr.Header().Class != dns.ClassINET || !strings.EqualFold(rr.Header().Name, q.Question[0].Name) {
			continue
		}
		generic, ok := rr.(*dns.RFC3597)
		if !ok {
			return nil, errors.New("IHLE type collides with a known DNS type")
		}
		raw, err := hex.DecodeString(generic.Rdata)
		if err != nil {
			return nil, err
		}
		if err := tokens.ValidateRecord(raw); err != nil {
			return nil, err
		}
		records = append(records, raw)
	}
	return records, nil
}
