package ihle

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/coredns/coredns/plugin/file"
	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
)

const zone = `$ORIGIN example.org.
$TTL 300
@ IN SOA ns.example.org. hostmaster.example.org. 1 3600 600 86400 300
@ IN NS ns.example.org.
ns IN A 192.0.2.53
www IN A 192.0.2.1
www IN AAAA 2001:db8::1
www IN TXT "ordinary zone data"
www IN TYPE65297 \# 3 a10101
www IN TYPE65297 \# 3 a10102
plain IN A 192.0.2.2
alias IN CNAME www.example.org.
`

func handler(t *testing.T, data string) IHLE {
	t.Helper()
	z, err := file.Parse(strings.NewReader(data), "example.org.", "test.zone", -1)
	if err != nil {
		t.Fatal(err)
	}
	return IHLE{TypeNum: 65297, Next: file.File{Zones: file.Zones{
		Z: map[string]*file.Zone{"example.org.": z}, Names: []string{"example.org."},
	}}}
}

func ask(t *testing.T, h IHLE, name string, qtype uint16, tcp bool, size uint16) *dns.Msg {
	t.Helper()
	r := new(dns.Msg)
	r.SetQuestion(name, qtype)
	if size != 0 {
		r.SetEdns0(size, false)
	}
	w := dnstest.NewRecorder(&test.ResponseWriter{TCP: tcp})
	if code, err := h.ServeDNS(context.Background(), request.NewScrubWriter(r, w), r); err != nil || code != dns.RcodeSuccess {
		t.Fatalf("ServeDNS returned %d, %v", code, err)
	}
	if w.Msg == nil {
		t.Fatal("no response written")
	}
	return w.Msg
}

func count(rrs []dns.RR, qtype uint16) int {
	n := 0
	for _, rr := range rrs {
		if rr.Header().Rrtype == qtype {
			n++
		}
	}
	return n
}

func TestZoneAnswers(t *testing.T) {
	h := handler(t, zone)
	for _, tt := range []struct {
		name          string
		qtype         uint16
		rcode         int
		answer, extra int
	}{
		{"www.example.org.", dns.TypeA, dns.RcodeSuccess, 1, 2},
		{"WWW.EXAMPLE.ORG.", dns.TypeAAAA, dns.RcodeSuccess, 1, 2},
		{"www.example.org.", dns.TypeTXT, dns.RcodeSuccess, 1, 2},
		{"www.example.org.", dns.TypeMX, dns.RcodeSuccess, 0, 2},
		{"www.example.org.", 65297, dns.RcodeSuccess, 2, 0},
		{"www.example.org.", dns.TypeANY, dns.RcodeSuccess, 0, 2},
		{"plain.example.org.", dns.TypeA, dns.RcodeSuccess, 1, 0},
		{"plain.example.org.", 65297, dns.RcodeSuccess, 0, 0},
		{"missing.example.org.", dns.TypeA, dns.RcodeNameError, 0, 0},
		{"alias.example.org.", dns.TypeA, dns.RcodeSuccess, 2, 0},
		{"example.org.", dns.TypeSOA, dns.RcodeSuccess, 1, 0},
		{"example.org.", dns.TypeNS, dns.RcodeSuccess, 1, 0},
	} {
		t.Run(fmt.Sprintf("%s/%d", tt.name, tt.qtype), func(t *testing.T) {
			m := ask(t, h, tt.name, tt.qtype, false, 1232)
			if m.Rcode != tt.rcode || !m.Authoritative || m.Truncated || len(m.Answer) != tt.answer || count(m.Extra, 65297) != tt.extra {
				t.Fatalf("unexpected response: %s", m)
			}
			if tt.extra == 2 && (m.Extra[0].(*dns.RFC3597).Rdata != "a10101" || m.Extra[1].(*dns.RFC3597).Rdata != "a10102") {
				t.Fatal("IHLE RDATA changed")
			}
			if tt.answer == 0 && len(m.Ns) == 0 {
				t.Fatal("negative response lost its authority records")
			}
		})
	}
}

func TestCompleteRRSetOnRetry(t *testing.T) {
	h := handler(t, zone+"www IN TYPE65297 \\# 600 "+strings.Repeat("00", 600)+"\n")
	for _, qtype := range []uint16{dns.TypeA, 65297, dns.TypeANY} {
		for _, size := range []uint16{0, 512} {
			m := ask(t, h, "www.example.org.", qtype, false, size)
			if !m.Truncated || count(m.Answer, 65297)+count(m.Extra, 65297) != 0 || m.Len() > 512 {
				t.Fatalf("oversized reply contains partial IHLE or lacks TC: %s", m)
			}
		}
		for _, tcp := range []bool{false, true} {
			m := ask(t, h, "www.example.org.", qtype, tcp, 1232)
			if m.Truncated || count(m.Answer, 65297)+count(m.Extra, 65297) != 3 {
				t.Fatalf("retry lacks complete IHLE RRset: %s", m)
			}
		}
	}
	// Truncating a reply must not mutate records stored in the zone backend.
	m := ask(t, h, "www.example.org.", dns.TypeA, true, 0)
	if count(m.Extra, 65297) != 3 {
		t.Fatal("zone data was modified by truncation")
	}
}
