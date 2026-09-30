// Package ihle adds an owner's complete IHLE RRset to DNS responses.
// Records are obtained from the next plugin, which handles ordinary DNS queries.
package ihle

import (
	"context"
	"slices"
	"strings"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
)

type IHLE struct {
	Next    plugin.Handler
	TypeNum uint16
}

func (ihle IHLE) Name() string { return "ihle" }

func (ihle IHLE) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	if r.Opcode != dns.OpcodeQuery ||
		// https://www.rfc-editor.org/rfc/rfc9619.html
		len(r.Question) != 1 ||
		// Exclude zone transfer
		r.Question[0].Qtype == dns.TypeAXFR || r.Question[0].Qtype == dns.TypeIXFR {
		return plugin.NextOrFailure(ihle.Name(), ihle.Next, ctx, w, r)
	}
	response := &capture{ResponseWriter: w}
	if code, err := plugin.NextOrFailure(ihle.Name(), ihle.Next, ctx, response, r); err != nil || response.msg == nil {
		return code, err
	}
	m := response.msg
	q := r.Question[0]
	matches := func(rr dns.RR) bool {
		return rr.Header().Rrtype == ihle.TypeNum && rr.Header().Class == q.Qclass && strings.EqualFold(rr.Header().Name, q.Name)
	}
	if q.Qtype != ihle.TypeNum && !slices.ContainsFunc(m.Answer, matches) {
		lookup := r.Copy()
		lookup.Question[0].Qtype = ihle.TypeNum
		rrset := &capture{ResponseWriter: w}
		if code, err := plugin.NextOrFailure(ihle.Name(), ihle.Next, ctx, rrset, lookup); err != nil || code != dns.RcodeSuccess {
			return dns.RcodeServerFailure, err
		}
		if rrset.msg != nil && slices.ContainsFunc(rrset.msg.Answer, matches) {
			for _, rr := range rrset.msg.Answer {
				if matches(rr) {
					m.Extra = append(m.Extra, rr)
				}
			}
		}
	}

	// CoreDNS's ordinary truncation may retain only part of an RRset. Remove
	// the entire IHLE RRset first and force TCP retry if the full reply won't fit.
	state := request.Request{W: w, Req: r.Copy()}
	state.SizeAndDo(m)
	m.Compress = true
	if m.Len() > state.Size() && (slices.ContainsFunc(m.Answer, matches) || slices.ContainsFunc(m.Extra, matches)) {
		m.Answer = slices.DeleteFunc(m.Answer, matches)
		m.Extra = slices.DeleteFunc(m.Extra, matches)
		m.Truncated = true
	}
	return dns.RcodeSuccess, w.WriteMsg(m)
}

// Capture backend replies without sending the internal IHLE lookup to the client.
type capture struct {
	dns.ResponseWriter
	msg *dns.Msg
}

func (c *capture) WriteMsg(m *dns.Msg) error {
	c.msg = m.Copy()
	return nil
}

func (c *capture) Write(b []byte) (int, error) {
	m := new(dns.Msg)
	if err := m.Unpack(b); err != nil {
		return 0, err
	}
	return len(b), c.WriteMsg(m)
}
