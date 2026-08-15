package dnsserver

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/yoshiofthewire/kydns-server/internal/zone"
)

// PolicyDecider is the blacklist policy's slice of the DNS pipeline. Keeping
// it an interface here means dnsserver never imports the policy package, and a
// test can block a name with six lines.
//
// decision is the query log's policy field: "allow", "deny", a list name, or
// "forwarded".
type PolicyDecider interface {
	Decide(name string) (blocked bool, decision string, ttl uint32)
}

type Options struct {
	Holder    *zone.Holder
	ACL       *ACL
	Auth      *Authoritative
	Forwarder *Forwarder
	// Policy is consulted only for names the authoritative lookup declines, so
	// a public list can never blackhole a local service. Nil means no filtering.
	Policy      PolicyDecider
	LogQueries  bool
	LogClientIP bool
	Logger      *slog.Logger
}

type Server struct {
	o           Options
	metrics     *Metrics
	logQueries  atomic.Bool
	logClientIP atomic.Bool
	mu          sync.Mutex
	srvs        []*dns.Server
}

func New(o Options) *Server {
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	s := &Server{o: o, metrics: NewMetrics()}
	s.SetLogging(o.LogQueries, o.LogClientIP)
	return s
}

// Metrics is the read side of the query counters, mirroring ACL.Stats.
func (s *Server) Metrics() *Metrics { return s.metrics }

// SetLogging changes both logging opt-ins. The client IP stays a separate
// choice from query logging: turning on one must never turn on the other.
func (s *Server) SetLogging(queries, clientIP bool) {
	s.logQueries.Store(queries)
	s.logClientIP.Store(clientIP)
}

// LogQueries and LogClientIP report the current logging opt-ins, mirroring
// Cache.Len and ACL.Stats as the read side of a live-tunable value.
func (s *Server) LogQueries() bool  { return s.logQueries.Load() }
func (s *Server) LogClientIP() bool { return s.logClientIP.Load() }

// ServeDNS is the whole pipeline: opcode and class checks, ACL, view
// resolution, authoritative lookup, then forwarding.
func (s *Server) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	start := time.Now()
	reply := func(m *dns.Msg, source, view, policy string) {
		// Every reply passes through here, so no path can forget the datagram
		// ceiling. Over-large answers are common now that DO=1 is forwarded.
		if _, udp := w.RemoteAddr().(*net.UDPAddr); udp {
			m.Truncate(clientUDPSize(r))
		}
		if err := w.WriteMsg(m); err != nil {
			s.o.Logger.Warn("write reply", "error", writeErrText(err, s.logClientIP.Load()))
		}
		d := time.Since(start)
		s.metrics.Record(source, m.Rcode, d)
		s.logQuery(r, m, w, source, view, policy, d)
	}
	fail := func(rcode int, source string) {
		m := new(dns.Msg)
		m.SetRcode(r, rcode)
		reply(m, source, "", "")
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
		reply(m, "authoritative", view, "local")
		return
	}

	// The name is not ours, so it would be forwarded. This is the only place
	// filtering applies, and it decides before anything leaves the machine.
	policy := ""
	if s.o.Policy != nil {
		blocked, decision, ttl := s.o.Policy.Decide(q.Name)
		policy = decision
		if blocked {
			m := new(dns.Msg)
			m.SetRcode(r, dns.RcodeNameError)
			m.Authoritative = false // the block is local policy, not zone data
			m.RecursionAvailable = true
			m.Ns = []dns.RR{blockSOA(q.Name, ttl)}
			reply(m, "blocked", view, decision)
			return
		}
	}

	if s.o.Forwarder == nil {
		fail(dns.RcodeServerFailure, "forward")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	edns := r.IsEdns0()
	resp, err := s.o.Forwarder.Resolve(ctx, q, edns != nil && edns.Do())
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
	if edns == nil {
		stripOPT(out)
	}
	reply(out, "forward", view, policy)
}

// sourceAddr extracts the client address, unmapped so v4-in-v6 peers match
// v4 rules and unzoned because netip.Prefix matches no zoned address at all:
// a link-local peer arrives as fe80::1%eth0, which would otherwise make
// fe80::/10 in allow_query unmatchable and miss every view.
func sourceAddr(w dns.ResponseWriter) netip.Addr {
	host, _, err := net.SplitHostPort(w.RemoteAddr().String())
	if err != nil {
		return netip.Addr{}
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap().WithZone("")
}

// writeErrText renders a WriteMsg error for logging. A *net.OpError's
// Error() embeds the peer address (net.OpError.Addr), which would leak the
// client IP through an ungated path — the same information log_client_ip
// exists to gate. Unless that flag is already on, the op and the underlying
// error are reported without it.
func writeErrText(err error, includeAddr bool) string {
	if includeAddr {
		return err.Error()
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return opErr.Op + ": " + opErr.Err.Error()
	}
	return err.Error()
}

// clientUDPSize is the datagram budget the client advertised. A client that
// sent no OPT record does not speak EDNS0, so 512 is its ceiling.
func clientUDPSize(r *dns.Msg) int {
	if edns := r.IsEdns0(); edns != nil {
		return int(edns.UDPSize())
	}
	return dns.MinMsgSize
}

// stripOPT removes the EDNS0 record from a response. The forwarder always
// speaks EDNS0 upstream, but a client that did not offer an OPT record must
// not be handed one back.
func stripOPT(m *dns.Msg) {
	extra := m.Extra[:0]
	for _, rr := range m.Extra {
		if rr.Header().Rrtype != dns.TypeOPT {
			extra = append(extra, rr)
		}
	}
	m.Extra = extra
}

// blockSOA synthesizes the authority record that lets a client cache a block.
// Its owner is the queried name, so the negative answer is cached for exactly
// that name and nothing wider.
func blockSOA(qname string, ttl uint32) *dns.SOA {
	n := dns.Fqdn(qname)
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: n, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: ttl},
		Ns:      n,
		Mbox:    n,
		Serial:  1,
		Refresh: 3600, Retry: 600, Expire: 604800, Minttl: ttl,
	}
}

// logQuery honors the two-flag policy: query logging is off by default, and
// the client IP needs its own separate flag. The policy field says which
// decision produced the answer; it never says who asked.
func (s *Server) logQuery(r, m *dns.Msg, w dns.ResponseWriter, source, view, policy string, d time.Duration) {
	if !s.logQueries.Load() || len(r.Question) == 0 {
		return
	}
	q := r.Question[0]
	args := []any{
		"qname", q.Name,
		"qtype", dns.TypeToString[q.Qtype],
		"rcode", dns.RcodeToString[m.Rcode],
		"source", source,
		"view", view,
		"policy", policy,
		"duration_ms", d.Milliseconds(),
	}
	if s.logClientIP.Load() {
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
