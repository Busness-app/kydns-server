package zone

import (
	"fmt"
	"log/slog"
	"net/netip"
	"strings"

	"github.com/Busness-app/kydns-server/internal/store"
)

// RR is one resolved record. Name is a normalized FQDN.
type RR struct {
	Name  string
	Type  string
	Value string
}

// Index is one view's resolved data.
type Index struct {
	Forward map[string][]RR
	Reverse map[string]string
}

// Lease is a DHCP-discovered name. Plan 3 populates these; Plan 1 passes none.
type Lease struct {
	Hostname string
	Address  string
}

type Input struct {
	Views        []store.View
	Services     []store.Service
	Records      []store.Record
	Leases       []Lease
	Zone         string
	ReverseZones []netip.Prefix
	Generation   uint32
}

type Snapshot struct {
	Generation   uint32
	Matcher      *Matcher
	Views        map[string]*Index
	Zone         string
	ReverseZones []netip.Prefix
}

// Build resolves every view's effective set. It is all-or-nothing: an error
// means the caller keeps serving the previous snapshot.
func Build(in Input, logger *slog.Logger) (*Snapshot, error) {
	if logger == nil {
		logger = slog.Default()
	}
	m, err := NewMatcher(in.Views)
	if err != nil {
		return nil, err
	}
	snap := &Snapshot{
		Generation:   in.Generation,
		Matcher:      m,
		Views:        map[string]*Index{},
		Zone:         strings.ToLower(in.Zone),
		ReverseZones: in.ReverseZones,
	}
	// "" is the default view, always present.
	for _, view := range append([]string{""}, m.Names()...) {
		idx, err := buildIndex(in, view, snap.Zone, logger)
		if err != nil {
			return nil, fmt.Errorf("view %q: %w", view, err)
		}
		snap.Views[view] = idx
	}
	return snap, nil
}

// pick returns the view-tagged entries when any exist, otherwise the untagged
// ones. This is the "untagged means everywhere" rule.
func pick[T any](view string, tagOf func(T) string, all []T) []T {
	var tagged, untagged []T
	for _, v := range all {
		switch tag := tagOf(v); {
		case view != "" && tag == view:
			tagged = append(tagged, v)
		case tag == "":
			untagged = append(untagged, v)
		}
	}
	if len(tagged) > 0 {
		return tagged
	}
	return untagged
}

func buildIndex(in Input, view, zone string, logger *slog.Logger) (*Index, error) {
	idx := &Index{Forward: map[string][]RR{}, Reverse: map[string]string{}}

	// Precedence is applied by writing in ascending priority and letting later
	// layers replace earlier ones: lease, then service/alias, then manual.
	for _, l := range in.Leases {
		name := qualify(l.Hostname, zone)
		idx.Forward[name] = []RR{{Name: name, Type: addrType(l.Address), Value: l.Address}}
		// A lease is a forward record, so it derives a PTR like any other.
		// Later layers overwrite it, which is precedence working.
		if addr, err := netip.ParseAddr(l.Address); err == nil && inZones(addr, in.ReverseZones) {
			idx.Reverse[arpaName(addr)] = name
		}
	}

	// Tracks which reverse keys this loop itself has written, so the
	// collision warning fires only for two services sharing an address, not
	// for a service overwriting a lease's PTR (that overwrite is precedence
	// working, per the comment above).
	written := map[string]bool{}
	// Tracks which forward names belong to a routed service, so a manual
	// record displacing one can be flagged: the service badge still claims
	// the proxy, but the manual record is what a client actually gets.
	routed := map[string]struct{ service, proxy string }{}
	for _, svc := range in.Services {
		addrs := pick(view, func(a store.Address) string { return a.View }, svc.Addresses)
		if len(addrs) == 0 {
			continue
		}
		primary := qualify(svc.Name, zone)

		// Forward records answer with the proxy when routed; reverse records
		// always name the real host, so several services behind one proxy
		// keep their own PTRs.
		answer := addrs
		if svc.RouteViaProxy && svc.ProxyAddress != "" {
			answer = []store.Address{{Address: svc.ProxyAddress}}
		}

		names := []string{primary}
		for _, alias := range svc.Aliases {
			names = append(names, qualify(alias, zone))
		}
		for _, n := range names {
			rrs := make([]RR, 0, len(answer))
			for _, a := range answer {
				rrs = append(rrs, RR{Name: n, Type: addrType(a.Address), Value: a.Address})
			}
			idx.Forward[n] = rrs
			if svc.RouteViaProxy && svc.ProxyAddress != "" {
				routed[n] = struct{ service, proxy string }{svc.Name, svc.ProxyAddress}
			}
		}

		// Only the primary name gets a PTR; aliases do not.
		for _, a := range addrs {
			addr, err := netip.ParseAddr(a.Address)
			if err != nil || !inZones(addr, in.ReverseZones) {
				continue
			}
			key := arpaName(addr)
			if prior, ok := idx.Reverse[key]; written[key] && ok && prior != primary {
				logger.Warn("two services share an address, so its reverse record is ambiguous",
					"address", a.Address, "previous", prior, "now", primary, "view", view,
					"fix", "give them different addresses, or set a proxy address on one")
			}
			idx.Reverse[key] = primary
			written[key] = true
		}
	}

	// The first manual record at a name displaces whatever the service or
	// lease layer put there; further records at that name accumulate, so a
	// multi-homed name keeps every address the operator authored.
	claimed := map[string]bool{}
	for _, r := range pick(view, func(r store.Record) string { return r.View }, in.Records) {
		name := strings.ToLower(r.Name)
		if r.Type == "PTR" {
			idx.Reverse[name] = strings.ToLower(r.Value)
			continue
		}
		rr := RR{Name: name, Type: r.Type, Value: strings.ToLower(r.Value)}
		if !claimed[name] {
			claimed[name] = true
			if svc, ok := routed[name]; ok {
				logger.Warn("a manual record displaces a routed service's forward answer",
					"service", svc.service, "name", name, "manual_value", rr.Value, "proxy_address", svc.proxy,
					"fix", "remove the manual record, or it will keep answering with the real address")
			}
			idx.Forward[name] = []RR{rr}
			continue
		}
		idx.Forward[name] = append(idx.Forward[name], rr)
	}

	for name, rrs := range idx.Forward {
		var hasCNAME, hasAddr bool
		for _, rr := range rrs {
			if rr.Type == "CNAME" {
				hasCNAME = true
			} else {
				hasAddr = true
			}
		}
		if hasCNAME && (hasAddr || len(rrs) > 1) {
			return nil, fmt.Errorf("%s: CNAME may not coexist with address records", name)
		}
	}
	return idx, nil
}

func addrType(s string) string {
	if a, err := netip.ParseAddr(s); err == nil && a.Is4() {
		return "A"
	}
	return "AAAA"
}

func qualify(name, zone string) string {
	n := strings.ToLower(strings.TrimSuffix(name, "."))
	if strings.HasSuffix(n+".", zone) {
		return n + "."
	}
	return n + "." + zone
}

func inZones(a netip.Addr, zones []netip.Prefix) bool {
	for _, z := range zones {
		if z.Contains(a) {
			return true
		}
	}
	return false
}

// arpaName renders the reverse FQDN for an address.
func arpaName(a netip.Addr) string {
	a = a.Unmap()
	if a.Is4() {
		b := a.As4()
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", b[3], b[2], b[1], b[0])
	}
	b := a.As16()
	var sb strings.Builder
	for i := len(b) - 1; i >= 0; i-- {
		fmt.Fprintf(&sb, "%x.%x.", b[i]&0xf, b[i]>>4)
	}
	sb.WriteString("ip6.arpa.")
	return sb.String()
}

// Lookup returns the records for name in view, falling back to the default
// view's index when the named view does not exist.
func (s *Snapshot) Lookup(view, name string) []RR {
	idx, ok := s.Views[view]
	if !ok {
		idx = s.Views[""]
	}
	return idx.Forward[strings.ToLower(name)]
}

// LookupPTR returns the target name for a reverse query, or "".
func (s *Snapshot) LookupPTR(view, arpa string) string {
	idx, ok := s.Views[view]
	if !ok {
		idx = s.Views[""]
	}
	return idx.Reverse[strings.ToLower(arpa)]
}

// HasName reports whether the name exists in the view with any type, which is
// how the handler distinguishes NODATA from NXDOMAIN.
func (s *Snapshot) HasName(view, name string) bool {
	return len(s.Lookup(view, name)) > 0
}
