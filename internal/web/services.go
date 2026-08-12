package web

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/yoshiofthewire/kydns-server/internal/health"
	"github.com/yoshiofthewire/kydns-server/internal/store"
)

type addressRow struct {
	Address string
	View    string // display text, never blank
	Tagged  bool
}

type serviceRow struct {
	ID            int64
	Name          string
	Addresses     []addressRow
	Aliases       string
	Health        string
	ProxyAddress  string
	RouteViaProxy bool
}

// allViews is what an untagged address is labelled. A blank cell reads as
// broken; "all views" reads as everywhere.
const allViews = "all views"

func (s *Server) servicesData(errMsg string) map[string]any {
	svcs, err := s.o.Registry.Services()
	if err != nil && errMsg == "" {
		errMsg = err.Error()
	}
	// Absent health data is "unknown", never a claim that everything is fine.
	states := map[int64]string{}
	if s.o.Health != nil {
		for _, st := range s.o.Health() {
			states[st.ServiceID] = st.State
		}
	}

	rows := make([]serviceRow, 0, len(svcs))
	for _, svc := range svcs {
		state := states[svc.ID]
		if state == "" {
			state = health.StateUnknown
		}
		row := serviceRow{
			ID: svc.ID, Name: svc.Name,
			Aliases: strings.Join(svc.Aliases, ", "), Health: state,
			ProxyAddress: svc.ProxyAddress, RouteViaProxy: svc.RouteViaProxy,
		}
		for _, a := range svc.Addresses {
			if a.View == "" {
				row.Addresses = append(row.Addresses, addressRow{Address: a.Address, View: allViews})
				continue
			}
			row.Addresses = append(row.Addresses, addressRow{Address: a.Address, View: a.View, Tagged: true})
		}
		rows = append(rows, row)
	}
	views, _ := s.o.Registry.Views()
	return map[string]any{
		"Title": "Services", "Nav": "services",
		"Services": rows, "Views": views, "Error": errMsg,
	}
}

func (s *Server) getServices(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "services.html", s.servicesData(""))
}

// renderServicesError re-renders the page with a field-level message rather
// than replacing it with a bare error page.
func (s *Server) renderServicesError(w http.ResponseWriter, r *http.Request, msg string) {
	w.WriteHeader(http.StatusBadRequest)
	s.render(w, r, "services.html", s.servicesData(msg))
}

func (s *Server) postServiceNew(w http.ResponseWriter, r *http.Request) {
	svc := store.Service{
		Name:     r.PostFormValue("name"),
		CheckURL: r.PostFormValue("check_url"),
		Addresses: []store.Address{{
			Address: r.PostFormValue("address"),
			View:    r.PostFormValue("view"),
		}},
	}
	svc.ProxyAddress = strings.TrimSpace(r.PostFormValue("proxy_address"))
	svc.RouteViaProxy = r.PostFormValue("route_via_proxy") != ""
	svc.CheckInsecure = r.PostFormValue("check_insecure") != ""
	if a := strings.TrimSpace(r.PostFormValue("aliases")); a != "" {
		for _, al := range strings.Split(a, ",") {
			if al = strings.TrimSpace(al); al != "" {
				svc.Aliases = append(svc.Aliases, al)
			}
		}
	}
	if _, err := s.o.Registry.PutService(svc); err != nil {
		s.renderServicesError(w, r, err.Error())
		return
	}
	http.Redirect(w, r, "/services", http.StatusSeeOther)
}

// postServiceAddress appends an address to an existing service, which is how
// a tailnet answer is added to a name that already resolves on the LAN.
func (s *Server) postServiceAddress(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PostFormValue("id"), 10, 64)
	if err != nil {
		s.renderServicesError(w, r, "invalid service id")
		return
	}
	svc, err := s.o.Registry.Service(id)
	if err != nil {
		s.renderServicesError(w, r, err.Error())
		return
	}
	svc.Addresses = append(svc.Addresses, store.Address{
		Address: r.PostFormValue("address"),
		View:    r.PostFormValue("view"),
	})
	if _, err := s.o.Registry.PutService(svc); err != nil {
		s.renderServicesError(w, r, err.Error())
		return
	}
	http.Redirect(w, r, "/services", http.StatusSeeOther)
}

func (s *Server) postServiceDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PostFormValue("id"), 10, 64)
	if err != nil {
		s.renderServicesError(w, r, "invalid service id")
		return
	}
	if err := s.o.Registry.DeleteService(id); err != nil {
		s.renderServicesError(w, r, err.Error())
		return
	}
	http.Redirect(w, r, "/services", http.StatusSeeOther)
}
