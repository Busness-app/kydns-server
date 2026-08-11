package dnsserver

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/yoshiofthewire/kydns-server/internal/zone"
)

type Options struct {
	Holder      *zone.Holder
	ACL         *ACL
	Auth        *Authoritative
	Forwarder   *Forwarder
	LogQueries  bool
	LogClientIP bool
	Logger      *slog.Logger
}

type Server struct {
	o    Options
	mu   sync.Mutex
	srvs []*dns.Server
}

func New(o Options) *Server {
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	return &Server{o: o}
}

// ServeDNS is the whole pipeline: opcode and class checks, ACL, view
// resolution, authoritative lookup, then forwarding.
func (s *Server) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	start := time.Now()
	reply := func(m *dns.Msg, source, view string) {
		if err := w.WriteMsg(m); err != nil {
			s.o.Logger.Warn("write reply", "error", err)
		}
		s.logQuery(r, m, w, source, view, time.Since(start))
	}
	fail := func(rcode int, source string) {
		m := new(dns.Msg)
		m.SetRcode(r, rcode)
		reply(m, source, "")
	}

	if r.Opcode != dns.OpcodeQuery {
		fail(dns.RcodeNotImplemented, "opcode")
		return
	}
	if len(r.Question) != 1 {
		fail(dns.RcodeFormatError, "question")
		return
	}
	q := r.Question[0]
	if q.Qclass != dns.ClassINET {
		fail(dns.RcodeRefused, "class")
		return
	}

	src := sourceAddr(w)
	if !s.o.ACL.Allow(src) {
		fail(dns.RcodeRefused, "acl")
		return
	}

	snap := s.o.Holder.Current()
	view := ""
	if snap != nil {
		view = snap.Matcher.Match(src)
	}

	if m := s.o.Auth.Answer(snap, view, q); m != nil {
		rcode := m.Rcode
		m.SetRcode(r, rcode)
		m.Authoritative = true
		reply(m, "authoritative", view)
		return
	}

	if s.o.Forwarder == nil {
		fail(dns.RcodeServerFailure, "forward")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := s.o.Forwarder.Resolve(ctx, q)
	if err != nil {
		s.o.Logger.Warn("forward failed", "qname", q.Name, "error", err)
		fail(dns.RcodeServerFailure, "forward")
		return
	}
	out := resp.Copy()
	rcode := resp.Rcode
	out.SetRcode(r, rcode)
	out.Authoritative = false
	out.RecursionAvailable = true
	reply(out, "forward", view)
}

// sourceAddr extracts the client address, unmapped so v4-in-v6 peers match
// v4 rules.
func sourceAddr(w dns.ResponseWriter) netip.Addr {
	host, _, err := net.SplitHostPort(w.RemoteAddr().String())
	if err != nil {
		return netip.Addr{}
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap()
}

// logQuery honors the two-flag policy: query logging is off by default, and
// the client IP needs its own separate flag.
func (s *Server) logQuery(r, m *dns.Msg, w dns.ResponseWriter, source, view string, d time.Duration) {
	if !s.o.LogQueries || len(r.Question) == 0 {
		return
	}
	q := r.Question[0]
	args := []any{
		"qname", q.Name,
		"qtype", dns.TypeToString[q.Qtype],
		"rcode", dns.RcodeToString[m.Rcode],
		"source", source,
		"view", view,
		"duration_ms", d.Milliseconds(),
	}
	if s.o.LogClientIP {
		args = append(args, "client", w.RemoteAddr().String())
	}
	s.o.Logger.Info("query", args...)
}

// ListenAndServe starts UDP and TCP listeners on addr and blocks until one
// fails.
func (s *Server) ListenAndServe(addr string) error {
	errs := make(chan error, 2)
	s.mu.Lock()
	for _, network := range []string{"udp", "tcp"} {
		srv := &dns.Server{Addr: addr, Net: network, Handler: s}
		s.srvs = append(s.srvs, srv)
		go func() { errs <- srv.ListenAndServe() }()
	}
	s.mu.Unlock()
	return <-errs
}

func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var joined error
	for _, srv := range s.srvs {
		if err := srv.ShutdownContext(ctx); err != nil {
			joined = errors.Join(joined, err)
		}
	}
	s.srvs = nil
	return joined
}
