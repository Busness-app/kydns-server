package web

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/Busness-app/kydns-server/internal/discovery/dhcp"
	"github.com/Busness-app/kydns-server/internal/registry"
	"github.com/Busness-app/kydns-server/internal/store"
)

// discoveryOn reports whether a lease source is configured right now. It is
// asked per request, because the built-in server and a lease file both come
// and go without a restart.
func (s *Server) discoveryOn() bool {
	return s.o.DiscoveryOn != nil && s.o.DiscoveryOn()
}

func (s *Server) leases() []dhcp.Lease {
	if s.o.Leases == nil {
		return nil
	}
	return s.o.Leases()
}

type leaseRow struct {
	Hostname string
	IP       string
	MAC      string
	Shadowed bool
}

// leaseRows marks each lease that something outranks. A shadowed lease is not
// resolving; saying so beats listing it as though it were live.
func (s *Server) leaseRows() ([]leaseRow, error) {
	if !s.discoveryOn() {
		return nil, nil
	}
	svcs, err := s.o.Registry.Services()
	if err != nil {
		return nil, err
	}
	// Anything that outranks a lease in the precedence rule: a manual record,
	// a service name, or an alias.
	taken := map[string]bool{}
	for _, svc := range svcs {
		taken[svc.Name] = true
		for _, a := range svc.Aliases {
			taken[a] = true
		}
	}
	recs, err := s.o.Registry.Records()
	if err != nil {
		return nil, err
	}
	for _, r := range recs {
		// Record names are FQDNs; leases are bare labels.
		if label, _, ok := strings.Cut(strings.TrimSuffix(r.Name, "."), "."); ok {
			taken[label] = true
		}
	}

	var rows []leaseRow
	for _, l := range s.leases() {
		rows = append(rows, leaseRow{
			Hostname: l.Hostname, IP: l.IP, MAC: l.MAC, Shadowed: taken[l.Hostname],
		})
	}
	return rows, nil
}

func (s *Server) discoveredData(errMsg string) map[string]any {
	rows, err := s.leaseRows()
	if err != nil && errMsg == "" {
		errMsg = err.Error()
	}
	return map[string]any{
		"Title": "Discovered", "Nav": "discovered",
		"Leases": rows, "Enabled": s.discoveryOn(), "Error": errMsg,
	}
}

func (s *Server) getDiscovered(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "discovered.html", s.discoveredData(""))
}

// promoteLease turns the lease at ip into a durable service. Leases are never
// persisted, so this is the only path from discovery into the database, and
// both the Discovered screen and the DHCP tab's Reserve button take it.
//
// The MAC comes with the address when it can: on the built-in server that is
// what pins the lease as a reservation, and with an external lease file it is
// inert, since the two cannot be on at once.
//
// ip names the lease; nothing else the form carries is trusted, because a
// posted address with no lease behind it would otherwise reserve whatever it
// named.
func (s *Server) promoteLease(ip string) error {
	if s.discoveryOn() {
		for _, l := range s.leases() {
			// An unnamed lease has nothing to call the service, so it is not a
			// candidate rather than an error of its own.
			if l.IP != ip || l.Hostname == "" {
				continue
			}
			_, err := s.o.Registry.PutService(store.Service{
				Name: l.Hostname, MAC: s.reservableMAC(l.MAC),
				Addresses: []store.Address{{Address: l.IP}},
			})
			return err
		}
	}
	return fmt.Errorf("no current lease for %s", ip)
}

// reservableMAC is the MAC to promote with, or "" for a name without a
// reservation. Promote's contract is the name; a lease identifier the registry
// would reject must not cost the operator that. Two identifiers reach here: a
// dnsmasq file holding DHCPv6 leases puts an IAID in the MAC column, and one
// device with two hostnames holds two leases on one MAC, which only one
// service may claim.
func (s *Server) reservableMAC(mac string) string {
	if mac == "" || registry.ValidateMAC(mac) != nil {
		return ""
	}
	svcs, err := s.o.Registry.Services()
	if err != nil {
		return ""
	}
	norm := registry.NormalizeMAC(mac)
	for _, svc := range svcs {
		if svc.MAC == norm {
			return ""
		}
	}
	return mac
}

func (s *Server) postPromote(w http.ResponseWriter, r *http.Request) {
	if err := s.promoteLease(r.PostFormValue("ip")); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		s.render(w, r, "discovered.html", s.discoveredData(err.Error()))
		return
	}
	http.Redirect(w, r, "/services", http.StatusSeeOther)
}
