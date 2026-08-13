package dnsserver

import (
	"net"
	"net/netip"
	"strings"
	"sync/atomic"

	"github.com/miekg/dns"
	"github.com/yoshiofthewire/kydns-server/internal/zone"
)

const cnameChaseDepth = 8

// Authoritative answers from the snapshot for names inside the private zone
// and the configured reverse zones. The zone, the TTL and the reverse zones
// are all read on every query, so all three are atomics rather than
// mutex-guarded fields.
type Authoritative struct {
	zone         atomic.Pointer[string]
	ttl          atomic.Uint32
	reverseZones atomic.Pointer[[]netip.Prefix]
}

// NewAuthoritative builds an Authoritative for zone, with the given initial
// TTL and reverse zones.
func NewAuthoritative(zone string, ttl uint32, reverse []netip.Prefix) *Authoritative {
	a := &Authoritative{}
	a.SetZone(zone)
	a.ttl.Store(ttl)
	a.SetReverseZones(reverse)
	return a
}

// Zone is the private zone, as an FQDN with a trailing dot.
func (a *Authoritative) Zone() string {
	if z := a.zone.Load(); z != nil {
		return *z
	}
	return ""
}

// SetZone changes the private zone. Answer reads the zone once at the top of
// each call, so one reply never straddles a change.
func (a *Authoritative) SetZone(zone string) {
	z := strings.ToLower(dns.Fqdn(zone))
	a.zone.Store(&z)
}

// SetTTL changes the TTL on authoritative answers. Answer snapshots the TTL
// once at the start of each call, so one in-flight answer never mixes two
// TTL values across its own records; a concurrent SetTTL only ever affects
// answers that start after it lands.
func (a *Authoritative) SetTTL(ttl uint32) { a.ttl.Store(ttl) }

// SetReverseZones changes which networks get derived PTR records.
func (a *Authoritative) SetReverseZones(z []netip.Prefix) {
	masked := make([]netip.Prefix, 0, len(z))
	for _, p := range z {
		masked = append(masked, p.Masked())
	}
	a.reverseZones.Store(&masked)
}

// Owns reports whether qname falls in a zone this server is authoritative for.
// A reverse name outside every configured reverse zone is not owned, so the
// pipeline forwards it instead of answering NXDOMAIN for the whole internet.
func (a *Authoritative) Owns(qname string) bool { return a.owns(a.Zone(), qname) }

// owns is Owns against an already-read zone, so one Answer call decides every
// name it touches against the same zone.
func (a *Authoritative) owns(zone, qname string) bool {
	n := strings.ToLower(dns.Fqdn(qname))
	if zone != "" && (n == zone || strings.HasSuffix(n, "."+zone)) {
		return true
	}
	if strings.HasSuffix(n, ".in-addr.arpa.") || strings.HasSuffix(n, ".ip6.arpa.") {
		addr, ok := addrFromArpa(n)
		if !ok {
			return false
		}
		zones := a.reverseZones.Load()
		if zones == nil { // zero-value Authoritative, never given a constructor call
			return false
		}
		for _, p := range *zones {
			if p.Contains(addr) {
				return true
			}
		}
	}
	return false
}

// SOA synthesizes the apex SOA. The serial is the snapshot generation, so it
// advances on every rebuild for free.
func (a *Authoritative) SOA(serial uint32) *dns.SOA {
	return a.soa(a.Zone(), serial, a.ttl.Load())
}

func (a *Authoritative) soa(zone string, serial, ttl uint32) *dns.SOA {
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: ttl},
		Ns:      "ns." + zone,
		Mbox:    "hostmaster." + zone,
		Serial:  serial,
		Refresh: 3600, Retry: 600, Expire: 604800, Minttl: ttl,
	}
}

// Answer builds the authoritative reply, or returns nil when the name is not
// ours and the caller should forward. The TTL is read once at the top, so a
// concurrent SetTTL cannot split one message across two TTL values.
func (a *Authoritative) Answer(snap *zone.Snapshot, view string, q dns.Question) *dns.Msg {
	zone := a.Zone()
	if snap == nil || !a.owns(zone, q.Name) {
		return nil
	}
	ttl := a.ttl.Load()
	m := new(dns.Msg)
	m.Authoritative = true
	m.Question = []dns.Question{q}
	name := strings.ToLower(dns.Fqdn(q.Name))

	if name == zone {
		switch q.Qtype {
		case dns.TypeSOA:
			m.Answer = []dns.RR{a.soa(zone, snap.Generation, ttl)}
		case dns.TypeNS:
			m.Answer = []dns.RR{&dns.NS{
				Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: ttl},
				Ns:  "ns." + zone,
			}}
		default:
			m.Ns = []dns.RR{a.soa(zone, snap.Generation, ttl)}
		}
		return m
	}

	if q.Qtype == dns.TypePTR {
		if target := snap.LookupPTR(view, name); target != "" {
			m.Answer = []dns.RR{&dns.PTR{
				Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: ttl},
				Ptr: dns.Fqdn(target),
			}}
			return m
		}
		m.Rcode = dns.RcodeNameError
		m.Ns = []dns.RR{a.soa(zone, snap.Generation, ttl)}
		return m
	}

	rrs := snap.Lookup(view, name)
	if len(rrs) == 0 {
		m.Rcode = dns.RcodeNameError
		m.Ns = []dns.RR{a.soa(zone, snap.Generation, ttl)}
		return m
	}

	// A CNAME is the only record at its name, so this branch is exclusive.
	if rrs[0].Type == "CNAME" {
		m.Answer = a.chase(zone, snap, view, name, rrs[0].Value, q.Qtype, 0, ttl)
		return m
	}

	for _, rr := range rrs {
		if converted := a.toRR(rr, q.Qtype, ttl); converted != nil {
			m.Answer = append(m.Answer, converted)
		}
	}
	if len(m.Answer) == 0 { // name exists, type does not: NODATA
		m.Ns = []dns.RR{a.soa(zone, snap.Generation, ttl)}
	}
	return m
}

// chase follows in-zone CNAME targets so the client gets one complete answer.
// Out-of-zone targets are returned alone for the client's resolver to continue.
func (a *Authoritative) chase(zn string, snap *zone.Snapshot, view, name, target string, qtype uint16, depth int, ttl uint32) []dns.RR {
	cname := &dns.CNAME{
		Hdr:    dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: ttl},
		Target: dns.Fqdn(target),
	}
	if depth >= cnameChaseDepth || qtype == dns.TypeCNAME || !a.owns(zn, target) {
		return []dns.RR{cname}
	}
	out := []dns.RR{cname}
	next := snap.Lookup(view, dns.Fqdn(target))
	for _, rr := range next {
		if rr.Type == "CNAME" {
			return append(out, a.chase(zn, snap, view, dns.Fqdn(target), rr.Value, qtype, depth+1, ttl)...)
		}
		if converted := a.toRR(rr, qtype, ttl); converted != nil {
			out = append(out, converted)
		}
	}
	return out
}

func (a *Authoritative) toRR(rr zone.RR, qtype uint16, ttl uint32) dns.RR {
	hdr := func(t uint16) dns.RR_Header {
		return dns.RR_Header{Name: rr.Name, Rrtype: t, Class: dns.ClassINET, Ttl: ttl}
	}
	switch rr.Type {
	case "A":
		if qtype != dns.TypeA && qtype != dns.TypeANY {
			return nil
		}
		return &dns.A{Hdr: hdr(dns.TypeA), A: net.ParseIP(rr.Value)}
	case "AAAA":
		if qtype != dns.TypeAAAA && qtype != dns.TypeANY {
			return nil
		}
		return &dns.AAAA{Hdr: hdr(dns.TypeAAAA), AAAA: net.ParseIP(rr.Value)}
	}
	return nil
}

// addrFromArpa parses a reverse name back into an address.
func addrFromArpa(name string) (netip.Addr, bool) {
	n := strings.TrimSuffix(strings.ToLower(name), ".")
	switch {
	case strings.HasSuffix(n, ".in-addr.arpa"):
		parts := strings.Split(strings.TrimSuffix(n, ".in-addr.arpa"), ".")
		if len(parts) != 4 {
			return netip.Addr{}, false
		}
		for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
			parts[i], parts[j] = parts[j], parts[i]
		}
		a, err := netip.ParseAddr(strings.Join(parts, "."))
		return a, err == nil
	case strings.HasSuffix(n, ".ip6.arpa"):
		nib := strings.Split(strings.TrimSuffix(n, ".ip6.arpa"), ".")
		if len(nib) != 32 {
			return netip.Addr{}, false
		}
		var sb strings.Builder
		for i := len(nib) - 1; i >= 0; i-- {
			sb.WriteString(nib[i])
			if i%4 == 0 && i != 0 {
				sb.WriteByte(':')
			}
		}
		a, err := netip.ParseAddr(sb.String())
		return a, err == nil
	}
	return netip.Addr{}, false
}
