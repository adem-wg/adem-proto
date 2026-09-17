package dns

import (
	"encoding/hex"
	"net"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	mdns "github.com/miekg/dns"
	"github.com/veraison/go-cose"
)

const testKey = "a50102200121582065eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d2258201e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c025820496bd8afadf307e5b08c64b0421bf9dc01528a344a43bda88fadd1669da253ec"

func validItem(t *testing.T) []byte {
	t.Helper()
	item, err := hex.DecodeString(testKey)
	if err != nil {
		t.Fatal(err)
	}
	return item
}

func largeValidItem(t *testing.T) []byte {
	t.Helper()
	payload, err := cbor.Marshal(map[string]any{
		"ver": 1,
		"prp": 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	message := cose.NewSign1Message()
	message.Payload = payload
	message.Signature = make([]byte, 600)
	item, err := message.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}
	return item
}

type responseWriter struct {
	remote net.Addr
	msg    *mdns.Msg
}

func (w *responseWriter) LocalAddr() net.Addr          { return &net.UDPAddr{} }
func (w *responseWriter) RemoteAddr() net.Addr         { return w.remote }
func (w *responseWriter) WriteMsg(msg *mdns.Msg) error { w.msg = msg.Copy(); return nil }
func (w *responseWriter) Write([]byte) (int, error)    { return 0, nil }
func (w *responseWriter) Close() error                 { return nil }
func (w *responseWriter) TsigStatus() error            { return nil }
func (w *responseWriter) TsigTimersOnly(bool)          {}
func (w *responseWriter) Hijack()                      {}

func query(name string, qtype uint16) *mdns.Msg {
	request := new(mdns.Msg)
	request.SetQuestion(mdns.Fqdn(name), qtype)
	return request
}

func TestHandlerIncludesIHLEInAdditionalSection(t *testing.T) {
	item := validItem(t)
	handler, err := NewHandler("example.com", 300, [][]byte{item, item})
	if err != nil {
		t.Fatal(err)
	}
	writer := &responseWriter{remote: &net.UDPAddr{}}
	handler.ServeDNS(writer, query("example.com", mdns.TypeA))
	if len(writer.msg.Answer) != 0 || len(writer.msg.Extra) != 2 {
		t.Fatalf("got %d answer and %d additional records, want 0 and 2", len(writer.msg.Answer), len(writer.msg.Extra))
	}
}

func TestMatchesAsset(t *testing.T) {
	assets := []string{"other.example.", "EXAMPLE.com"}
	if !MatchesAsset("example.COM.", assets) {
		t.Fatal("equivalent FQDN did not match")
	}
	if MatchesAsset("not-example.com", assets) {
		t.Fatal("different FQDN matched")
	}
}

func TestNewIHLERejectsOtherCBOR(t *testing.T) {
	if _, err := NewIHLE("example.com", 300, []byte{0x01}); err == nil {
		t.Fatal("accepted CBOR that is neither an ADEM CWT nor a COSE_Key")
	}
}

func TestHandlerAnswersIHLEQuery(t *testing.T) {
	item := validItem(t)
	handler, err := NewHandler("example.com", 300, [][]byte{item, item})
	if err != nil {
		t.Fatal(err)
	}
	writer := &responseWriter{remote: &net.UDPAddr{}}
	handler.ServeDNS(writer, query("example.com", TypeIHLE))
	if len(writer.msg.Answer) != 2 || len(writer.msg.Extra) != 0 {
		t.Fatalf("got %d answer and %d additional records, want 2 and 0", len(writer.msg.Answer), len(writer.msg.Extra))
	}
}

func TestHandlerDoesNotReturnPartialRRSet(t *testing.T) {
	item := validItem(t)
	handler, err := NewHandler("example.com", 300, [][]byte{largeValidItem(t), item})
	if err != nil {
		t.Fatal(err)
	}
	writer := &responseWriter{remote: &net.UDPAddr{}}
	handler.ServeDNS(writer, query("example.com", mdns.TypeA))
	if !writer.msg.Truncated {
		t.Fatal("oversized UDP response did not set TC")
	}
	if len(writer.msg.Answer) != 0 || len(writer.msg.Extra) != 0 {
		t.Fatal("truncated response contains a partial IHLE RRset")
	}

	tcpWriter := &responseWriter{remote: &net.TCPAddr{}}
	handler.ServeDNS(tcpWriter, query("example.com", mdns.TypeA))
	if tcpWriter.msg.Truncated || len(tcpWriter.msg.Extra) != 2 {
		t.Fatal("TCP response does not contain the complete IHLE RRset")
	}
}

func TestLookupReadsAdditionalIHLERecords(t *testing.T) {
	item := validItem(t)
	handler, err := NewHandler("example.com", 300, [][]byte{item, item})
	if err != nil {
		t.Fatal(err)
	}
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("local UDP unavailable: %v", err)
	}
	server := &mdns.Server{PacketConn: packet, Handler: handler}
	done := make(chan error, 1)
	go func() { done <- server.ActivateAndServe() }()
	t.Cleanup(func() {
		_ = server.Shutdown()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("DNS server did not stop")
		}
	})

	tokens, err := Lookup("example.com", packet.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	if len(tokens) != 2 || hex.EncodeToString(tokens[0]) != testKey || hex.EncodeToString(tokens[1]) != testKey {
		t.Fatalf("unexpected tokens: %x", tokens)
	}
}
