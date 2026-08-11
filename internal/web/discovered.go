package web

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/yoshiofthewire/kydns-server/internal/store"
)

type leaseRow struct {
	Hostname string
	IP       string
	MAC      string
	Shadowed bool
}

// leaseRows marks each lease that something outranks. A shadowed lease is not
// resolving; saying so beats listing it as though it were live.
func (s *Server) leaseRows() ([]leaseRow, error) {
	if s.o.Leases == nil {
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
	for _, l := range s.o.Leases() {
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
		"Leases": rows, "Enabled": s.o.Leases != nil, "Error": errMsg,
	}
}

func (s *Server) getDiscovered(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "discovered.html", s.discoveredData(""))
}

// postPromote turns a lease into a durable service. Leases are never
// persisted, so promotion is the only path from discovery into the database.
func (s *Server) postPromote(w http.ResponseWriter, r *http.Request) {
	ip := r.PostFormValue("ip")
	var hostname string
	if s.o.Leases != nil {
		for _, l := range s.o.Leases() {
			if l.IP == ip {
				hostname = l.Hostname
				break
			}
		}
	}
	if hostname == "" {
		w.WriteHeader(http.StatusBadRequest)
		s.render(w, r, "discovered.html",
			s.discoveredData(fmt.Sprintf("No current lease for %s.", ip)))
		return
	}
	if _, err := s.o.Registry.PutService(store.Service{
		Name:      hostname,
		Addresses: []store.Address{{Address: ip}},
	}); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		s.render(w, r, "discovered.html", s.discoveredData(err.Error()))
		return
	}
	http.Redirect(w, r, "/services", http.StatusSeeOther)
}
