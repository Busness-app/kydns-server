package adminapi

import (
	"errors"
	"net/http"
	"net/netip"

	"github.com/yoshiofthewire/kydns-server/internal/dhcpd"
)

// DHCPRunner is the built-in server's runner as the API reads it. It is the
// runner's own method set rather than a mirrored struct: unlike ReplicaStatus
// there is no import cycle here, so nothing has to be kept in step by hand.
type DHCPRunner interface {
	Status() (bool, error)
	Foreign() []dhcpd.Foreign
	Problems() []dhcpd.ReservationProblem
}

// WithDHCP attaches the built-in server's runner. It is optional: a build
// with no runner reports not running, which is what such a node is.
func (a *API) WithDHCP(run DHCPRunner) *API {
	a.dhcp = run
	return a
}

// DHCPStatus is everything the DHCP tab needs in one request: whether the
// listener is running, whether it could, what is standing in the way, and the
// caveats worth telling the operator about. GET /api/v1/leases answers none
// of it: "off" and "refused to start" both show an empty lease table, and
// only the second has a reason to act on.
type DHCPStatus struct {
	Running   bool          `json:"running"`
	Error     string        `json:"error,omitempty"`
	Supported bool          `json:"supported"`
	Reason    string        `json:"reason,omitempty"`
	Foreign   []DHCPForeign `json:"foreign"`
	Problems  []DHCPProblem `json:"problems"`
	DualStack bool          `json:"dual_stack"`
}

// DHCPForeign is another DHCP server answering on this segment.
type DHCPForeign struct {
	Server  string `json:"server"`
	Offered string `json:"offered"`
}

// DHCPProblem is a reservation that could not be resolved. Reason is shown
// verbatim, so it says what to do rather than what went wrong.
type DHCPProblem struct {
	Service string `json:"service"`
	MAC     string `json:"mac"`
	Reason  string `json:"reason"`
}

// DHCPStatus reads the built-in server's state. Exported for the DHCP tab, so
// the screen and the JSON endpoint are one computation: two of them would let
// the two surfaces disagree about whether DHCP is running.
func (a *API) DHCPStatus() DHCPStatus {
	// Both slices are initialized, not nil: the UI ranges over them, and a
	// JSON null there is an error rather than an empty table.
	out := DHCPStatus{Foreign: []DHCPForeign{}, Problems: []DHCPProblem{}}
	if a.dhcp != nil {
		running, err := a.dhcp.Status()
		out.Running = running
		if err != nil {
			out.Error = err.Error()
		}
		for _, f := range a.dhcp.Foreign() {
			out.Foreign = append(out.Foreign, DHCPForeign{
				Server: addrText(f.ServerID), Offered: addrText(f.Offered),
			})
		}
		for _, p := range a.dhcp.Problems() {
			out.Problems = append(out.Problems, DHCPProblem{
				Service: p.Service, MAC: p.MAC, Reason: p.Reason,
			})
		}
	}
	if a.settings != nil {
		if v, err := a.settings.Get(); err == nil && v.DHCPInterface != "" {
			if err := dhcpd.Qualifies(v.DHCPInterface); err != nil {
				out.Reason = err.Error()
			} else {
				out.Supported = true
				if info, err := dhcpd.Inspect(v.DHCPInterface); err == nil {
					out.DualStack = info.HasGlobalIPv6
				}
			}
		}
	}
	return out
}

func (a *API) getDHCPStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, a.DHCPStatus())
}

// DHCPSuggestion is the setup wizard's prefill. Every field is a proposal the
// operator confirms; nothing here is applied.
type DHCPSuggestion struct {
	Interface    string `json:"interface"`
	Subnet       string `json:"subnet"`
	RangeStart   string `json:"range_start"`
	RangeEnd     string `json:"range_end"`
	Gateway      string `json:"gateway"`
	LeaseSeconds int    `json:"lease_seconds"`
	DualStack    bool   `json:"dual_stack"`
}

// SuggestedLeaseSeconds is not arbitrary: clients renew at half the lease, so
// an outage has roughly twelve hours before anything loses its address. It is
// also what the tab's form offers before anything has been saved.
const SuggestedLeaseSeconds = 86400

// DHCPSuggest proposes a configuration for one interface. Exported for the
// tab's wizard button: Qualifies passing does not mean a range can be cut out
// of the subnet, and only this path holds both answers.
func DHCPSuggest(name string) (DHCPSuggestion, error) {
	if name == "" {
		return DHCPSuggestion{}, errors.New("interface is required")
	}
	// Qualifies first: its message names the deployment problem, which is
	// what the wizard shows in place of the form.
	if err := dhcpd.Qualifies(name); err != nil {
		return DHCPSuggestion{}, err
	}
	info, err := dhcpd.Inspect(name)
	if err != nil {
		return DHCPSuggestion{}, err
	}
	start, end, err := dhcpd.SuggestRange(info.Subnet)
	if err != nil {
		return DHCPSuggestion{}, err
	}
	return DHCPSuggestion{
		Interface:    name,
		Subnet:       info.Subnet.String(),
		RangeStart:   start.String(),
		RangeEnd:     end.String(),
		Gateway:      addrText(info.Gateway),
		LeaseSeconds: SuggestedLeaseSeconds,
		DualStack:    info.HasGlobalIPv6,
	}, nil
}

func (a *API) dhcpSuggest(w http.ResponseWriter, r *http.Request) {
	sug, err := DHCPSuggest(r.URL.Query().Get("interface"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid", "interface", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, sug)
}

// addrText renders an address for the UI. A zero Addr stringifies as
// "invalid IP", which is not something to put in front of an operator: an
// absent gateway or an OFFER carrying no address is simply blank.
func addrText(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}
