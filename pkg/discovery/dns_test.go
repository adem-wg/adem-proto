package discovery

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net"
	"testing"

	"github.com/adem-wg/adem-proto/pkg/gen"
	"github.com/adem-wg/adem-proto/pkg/tokens"
	"github.com/adem-wg/adem-proto/pkg/vfy"
	"github.com/miekg/dns"
	"github.com/veraison/go-cose"
)

func testRecords(t *testing.T) ([][]byte, *cose.Key) {
	t.Helper()
	sk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := cose.NewKeyFromPrivate(sk)
	if err != nil {
		t.Fatal(err)
	}
	key.Algorithm = cose.AlgorithmES256
	proto, err := tokens.ParseClaims([]byte(`{"ver":1,"prp":1,"assets":["example.test"]}`))
	if err != nil {
		t.Fatal(err)
	}
	_, emblem, err := gen.SignEmblem(key, cose.AlgorithmES256, proto, 3600)
	if err != nil {
		t.Fatal(err)
	}
	carrier, err := tokens.EncodePublicCOSEKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return [][]byte{emblem, carrier}, key
}

type responseWriter struct {
	message *dns.Msg
	tcp     bool
}

func (w *responseWriter) LocalAddr() net.Addr { return &net.UDPAddr{} }
func (w *responseWriter) RemoteAddr() net.Addr {
	if w.tcp {
		return &net.TCPAddr{}
	}
	return &net.UDPAddr{}
}
func (w *responseWriter) WriteMsg(m *dns.Msg) error   { w.message = m; return nil }
func (w *responseWriter) Write(b []byte) (int, error) { return len(b), nil }
func (w *responseWriter) Close() error                { return nil }
func (w *responseWriter) TsigStatus() error           { return nil }
func (w *responseWriter) TsigTimersOnly(bool)         {}
func (w *responseWriter) Hijack()                     {}

func count(rrs []dns.RR, typ uint16) int {
	n := 0
	for _, rr := range rrs {
		if rr.Header().Rrtype == typ {
			n++
		}
	}
	return n
}
func TestAdditionalAndTruncation(t *testing.T) {
	records, _ := testRecords(t)
	h, err := NewHandler("example.test", dns.ClassINET, DefaultType, 60, records, net.ParseIP("127.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	for _, qt := range []uint16{DefaultType, dns.TypeA, dns.TypeAAAA, dns.TypeTXT, dns.TypeMX, dns.TypeANY} {
		q := new(dns.Msg)
		q.SetQuestion("EXAMPLE.test.", qt)
		w := &responseWriter{tcp: true}
		h.ServeDNS(w, q)
		if !w.message.Authoritative || w.message.Truncated {
			t.Fatal("bad complete reply")
		}
		answer, extra := count(w.message.Answer, DefaultType), count(w.message.Extra, DefaultType)
		if qt == DefaultType || qt == dns.TypeANY {
			if answer != 2 || extra != 0 {
				t.Fatal("IHLE answer duplicated or missing")
			}
		} else {
			if answer != 0 || extra != 2 {
				t.Fatal("IHLE not added")
			}
		}
	}
	// Force a response larger than both legacy and EDNS UDP limits.
	h.Records = append(h.Records, records...)
	h.Records = append(h.Records, h.Records...)
	for _, edns := range []bool{false, true} {
		q := new(dns.Msg)
		q.SetQuestion("example.test.", dns.TypeA)
		if edns {
			q.SetEdns0(1232, false)
		}
		w := &responseWriter{}
		h.ServeDNS(w, q)
		if !w.message.Truncated || count(w.message.Extra, DefaultType) != 0 {
			t.Fatal("partial RRset or missing TC")
		}
		w.tcp = true
		h.ServeDNS(w, q)
		if w.message.Truncated || count(w.message.Extra, DefaultType) != len(h.Records) {
			t.Fatal("TCP lost records")
		}
	}
	q := new(dns.Msg)
	q.SetQuestion("example.test.", dns.TypeA)
	q.Question[0].Qclass = dns.ClassCHAOS
	w := &responseWriter{tcp: true}
	h.ServeDNS(w, q)
	if count(w.message.Extra, DefaultType) != 0 || w.message.Rcode != dns.RcodeRefused {
		t.Fatal("wrong class served")
	}
	q.Question[0].Qclass = dns.ClassINET
	q.Question[0].Name = "other.test."
	h.ServeDNS(w, q)
	if count(w.message.Extra, DefaultType) != 0 {
		t.Fatal("wrong owner served")
	}
}

func TestProbeLocalUDPAndTCP(t *testing.T) {
	records, key := testRecords(t)
	// Several key records force TCP fallback, without introducing extra emblems.
	for range 24 {
		records = append(records, records[1])
	}
	h, err := NewHandler("example.test", dns.ClassINET, DefaultType, 60, records, net.ParseIP("127.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	packet, err := net.ListenPacket("udp", listener.Addr().String())
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	readyTCP, readyUDP := make(chan struct{}), make(chan struct{})
	tcp := &dns.Server{Listener: listener, Handler: h, NotifyStartedFunc: func() { close(readyTCP) }}
	udp := &dns.Server{PacketConn: packet, Handler: h, NotifyStartedFunc: func() { close(readyUDP) }}
	errs := make(chan error, 2)
	go func() { errs <- tcp.ActivateAndServe() }()
	go func() { errs <- udp.ActivateAndServe() }()
	<-readyTCP
	<-readyUDP
	t.Cleanup(func() {
		tcp.Shutdown()
		udp.Shutdown()
		for range 2 {
			if err := <-errs; err != nil {
				t.Error(err)
			}
		}
	})
	for _, qt := range []uint16{DefaultType, dns.TypeA} {
		got, err := Probe("example.test", listener.Addr().String(), qt, DefaultType)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != len(records) {
			t.Fatalf("incomplete RRset: %d", len(got))
		}
		if _, err := vfy.VerifierFor(got[0], key).Verify(); err != nil {
			t.Fatal(err)
		}
		carrier, err := tokens.DecodePublicCOSEKey(got[1])
		if err != nil {
			t.Fatal(err)
		}
		if _, err := vfy.VerifierFor(got[0], carrier).Verify(); err != nil {
			t.Fatal(err)
		}
	}
}
