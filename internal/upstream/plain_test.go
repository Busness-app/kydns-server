package upstream

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// query is the request every transport test sends.
func query() *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion("a.example.com.", dns.TypeA)
	return m
}

// answer is the reply every transport test expects back.
func answer(req *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(req)
	rr, err := dns.NewRR("a.example.com. 300 IN A 203.0.113.7")
	if err != nil {
		panic(err)
	}
	m.Answer = []dns.RR{rr}
	return m
}

func wantAnswer(t *testing.T, resp *dns.Msg, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("Answer = %v, want one record", resp.Answer)
	}
	if a, ok := resp.Answer[0].(*dns.A); !ok || a.A.String() != "203.0.113.7" {
		t.Fatalf("Answer[0] = %v, want 203.0.113.7", resp.Answer[0])
	}
}

// plainServer starts UDP and TCP DNS listeners on one address. Both are needed
// because the truncation retry crosses from one to the other.
func plainServer(t *testing.T, udpHandler, tcpHandler dns.HandlerFunc) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenPacket("udp", l.Addr().String())
	if err != nil {
		l.Close()
		t.Fatal(err)
	}
	udp := &dns.Server{PacketConn: pc, Handler: udpHandler}
	tcp := &dns.Server{Listener: l, Handler: tcpHandler}
	go udp.ActivateAndServe()
	go tcp.ActivateAndServe()
	t.Cleanup(func() { udp.Shutdown(); tcp.Shutdown() })
	return l.Addr().String()
}

func TestPlainRoundTrip(t *testing.T) {
	addr := plainServer(t,
		func(w dns.ResponseWriter, r *dns.Msg) { w.WriteMsg(answer(r)) },
		func(w dns.ResponseWriter, r *dns.Msg) { w.WriteMsg(answer(r)) })

	u, err := New(Spec{Raw: addr, Transport: Plain, Addr: addr}, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if u.Secure() {
		t.Error("Secure() = true for plaintext; an answer over UDP cannot be authenticated")
	}
	if u.String() != addr {
		t.Errorf("String() = %q, want %q", u.String(), addr)
	}
	resp, err := u.Exchange(context.Background(), query())
	wantAnswer(t, resp, err)
}

// A truncated UDP reply must be retried over TCP.
func TestPlainRetriesTruncatedOverTCP(t *testing.T) {
	tcpCalls := 0
	addr := plainServer(t,
		func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(r)
			m.Truncated = true
			w.WriteMsg(m)
		},
		func(w dns.ResponseWriter, r *dns.Msg) {
			tcpCalls++
			w.WriteMsg(answer(r))
		})

	u, _ := New(Spec{Raw: addr, Transport: Plain, Addr: addr}, 2*time.Second)
	resp, err := u.Exchange(context.Background(), query())
	wantAnswer(t, resp, err)
	if tcpCalls != 1 {
		t.Errorf("TCP calls = %d, want 1", tcpCalls)
	}
}

func TestNewAll(t *testing.T) {
	ups, err := NewAll([]string{"udp://192.168.1.1:53", "1.1.1.1:53"}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(ups) != 2 {
		t.Fatalf("NewAll() returned %d upstreams, want 2", len(ups))
	}
	for _, u := range ups {
		if u.Secure() {
			t.Errorf("%s.Secure() = true, want false", u)
		}
	}
	if _, err := NewAll([]string{"nope://x"}, time.Second); err == nil {
		t.Error("NewAll() error = nil with a bad entry")
	}
}

func TestNewRejectsUnbuildableTransport(t *testing.T) {
	_, err := New(Spec{Raw: "x", Transport: Transport(99)}, time.Second)
	if err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Errorf("New() error = %v, want an unsupported-transport rejection", err)
	}
}
