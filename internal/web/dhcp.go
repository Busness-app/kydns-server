package web

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Busness-app/kydns-server/internal/adminapi"
	"github.com/Busness-app/kydns-server/internal/registry"
	"github.com/Busness-app/kydns-server/internal/settings"
	"github.com/Busness-app/kydns-server/internal/store"
)

// errSettingsUnread is what a save is refused with when the current settings
// cannot be read: this form rebuilds the whole document, so writing without a
// baseline would blank every setting it does not carry.
var errSettingsUnread = errors.New(
	"the current settings could not be read, so this save was not applied; try again")

// dhcpForm is the settings form's contents: the stored values, what the
// operator typed back after a rejected save, or what the wizard proposed.
type dhcpForm struct {
	Enabled      bool
	Interface    string
	RangeStart   string
	RangeEnd     string
	Gateway      string
	LeaseSeconds int
	SecondaryDNS string
	AllowForeign bool
}

func dhcpFormOf(v store.Settings) dhcpForm {
	f := dhcpForm{
		Enabled: v.DHCPEnabled, Interface: v.DHCPInterface,
		RangeStart: v.DHCPRangeStart, RangeEnd: v.DHCPRangeEnd,
		Gateway: v.DHCPGateway, LeaseSeconds: v.DHCPLeaseSeconds,
		SecondaryDNS: v.DHCPSecondaryDNS, AllowForeign: v.DHCPAllowForeign,
	}
	// Nothing saved yet: offer the same lease time the wizard would, rather
	// than a zero that every first save is rejected for.
	if f.LeaseSeconds == 0 {
		f.LeaseSeconds = adminapi.SuggestedLeaseSeconds
	}
	return f
}

func dhcpFormFrom(r *http.Request) (dhcpForm, error) {
	f := dhcpForm{
		// An unchecked box posts nothing, so presence is the value. Reading it
		// any other way makes a toggle that can be turned on and never off.
		Enabled:      r.PostFormValue("enabled") != "",
		Interface:    strings.TrimSpace(r.PostFormValue("interface")),
		RangeStart:   strings.TrimSpace(r.PostFormValue("range_start")),
		RangeEnd:     strings.TrimSpace(r.PostFormValue("range_end")),
		Gateway:      strings.TrimSpace(r.PostFormValue("gateway")),
		SecondaryDNS: strings.TrimSpace(r.PostFormValue("secondary_dns")),
		AllowForeign: r.PostFormValue("allow_foreign") != "",
	}
	n, err := intField(r, "lease_seconds")
	f.LeaseSeconds = n
	return f, err
}

// apply lays the form over the running settings, so a DHCP save carries every
// unrelated setting through untouched.
func (f dhcpForm) apply(v store.Settings) store.Settings {
	v.DHCPEnabled, v.DHCPInterface = f.Enabled, f.Interface
	v.DHCPRangeStart, v.DHCPRangeEnd = f.RangeStart, f.RangeEnd
	v.DHCPGateway, v.DHCPLeaseSeconds = f.Gateway, f.LeaseSeconds
	v.DHCPSecondaryDNS, v.DHCPAllowForeign = f.SecondaryDNS, f.AllowForeign
	return v
}

// dhcpLeaseRow is one lease as the table shows it.
type dhcpLeaseRow struct {
	MAC      string
	IP       string
	Hostname string
	Expires  string
	Reserved bool // a service already holds this MAC
}

// leaseExpiry reads as time remaining: an expiry is a countdown, and
// sinceText's "ago" form would render every live lease as the past.
func leaseExpiry(at, now time.Time) string {
	if !at.After(now) {
		return "expired"
	}
	return "in " + shortDuration(at.Sub(now))
}

// dhcpLeaseRows marks each lease a service already reserves, so the tab does
// not offer to reserve the same MAC twice.
func (s *Server) dhcpLeaseRows(now time.Time) ([]dhcpLeaseRow, error) {
	svcs, err := s.o.Registry.Services()
	if err != nil {
		return nil, err
	}
	reserved := map[string]bool{}
	for _, svc := range svcs {
		if svc.MAC != "" {
			reserved[svc.MAC] = true
		}
	}
	var rows []dhcpLeaseRow
	for _, l := range s.leases() {
		rows = append(rows, dhcpLeaseRow{
			MAC: l.MAC, IP: l.IP, Hostname: l.Hostname,
			Expires:  leaseExpiry(l.Expires, now),
			Reserved: reserved[registry.NormalizeMAC(l.MAC)],
		})
	}
	return rows, nil
}

// dhcpStatus reads the state through the API, which computes it once for the
// JSON endpoint and for this page. A build with no API wired reports nothing
// running, which is what such a node is.
func (s *Server) dhcpStatus() adminapi.DHCPStatus {
	if s.o.API == nil {
		return adminapi.DHCPStatus{}
	}
	return s.o.API.DHCPStatus()
}

// dhcpData assembles the page in one pass, so the template has no logic beyond
// ranging and truthiness.
func (s *Server) dhcpData(form dhcpForm, st adminapi.DHCPStatus, errMsg string) map[string]any {
	rows, err := s.dhcpLeaseRows(time.Now())
	if err != nil && errMsg == "" {
		errMsg = err.Error()
	}
	return map[string]any{
		"Title": "DHCP", "Nav": "dhcp", "Form": form, "Leases": rows,
		"Running": st.Running, "StartError": st.Error,
		"Supported": st.Supported, "Reason": st.Reason, "DualStack": st.DualStack,
		"Foreign": st.Foreign, "Problems": st.Problems,
		"Error": errMsg,
	}
}

// renderDHCP draws the tab with whatever the caller has to add to it.
func (s *Server) renderDHCP(w http.ResponseWriter, r *http.Request, status int, form dhcpForm, errMsg string) {
	if status != http.StatusOK {
		w.WriteHeader(status)
	}
	s.render(w, r, "dhcp.html", s.dhcpData(form, s.dhcpStatus(), errMsg))
}

func (s *Server) getDHCP(w http.ResponseWriter, r *http.Request) {
	v, ok := s.liveSettings()
	if !ok {
		s.renderDHCP(w, r, http.StatusOK, dhcpFormOf(store.Settings{}), errSettingsUnread.Error())
		return
	}
	s.renderDHCP(w, r, http.StatusOK, dhcpFormOf(v), "")
}

// postDHCPSuggest fills the form in from the chosen interface and saves
// nothing: the operator reads the proposal and confirms it with Save.
func (s *Server) postDHCPSuggest(w http.ResponseWriter, r *http.Request) {
	// A lease time that will not parse is not why this button was pressed, and
	// the suggestion replaces it anyway.
	form, _ := dhcpFormFrom(r)
	sug, err := adminapi.DHCPSuggest(form.Interface)
	if err != nil {
		s.renderDHCP(w, r, http.StatusBadRequest, form, err.Error())
		return
	}
	form.RangeStart, form.RangeEnd = sug.RangeStart, sug.RangeEnd
	form.Gateway, form.LeaseSeconds = sug.Gateway, sug.LeaseSeconds
	s.renderDHCP(w, r, http.StatusOK, form, "")
}

func (s *Server) postDHCPSettings(w http.ResponseWriter, r *http.Request) {
	if s.o.Settings == nil {
		http.Error(w, "settings are not wired", http.StatusInternalServerError)
		return
	}
	form, err := dhcpFormFrom(r)
	if err != nil {
		s.renderDHCP(w, r, http.StatusBadRequest, form, err.Error())
		return
	}
	cur, ok := s.liveSettings()
	if !ok {
		s.renderDHCP(w, r, http.StatusBadRequest, form, errSettingsUnread.Error())
		return
	}
	// No confirmation: this form cannot widen allow_query, so there is no
	// exposure for the operator to authorize.
	if err := s.o.Settings.Set(form.apply(cur), ""); err != nil {
		status, reason := s.dhcpSaveRefusal(err)
		s.renderDHCP(w, r, status, form, reason)
		return
	}
	http.Redirect(w, r, "/dhcp", http.StatusSeeOther)
}

// dhcpSaveRefusal is how a refused save is shown. A replica may save this form,
// so the only way it is refused as read-only is a pull landing between the read
// above and the write, which moved the non-DHCP half the form carried: the same
// 409 the API answers that with, and the address of the box the rest of the
// settings belong on, which nothing else on this tab shows.
func (s *Server) dhcpSaveRefusal(err error) (int, string) {
	if !errors.Is(err, settings.ErrReadOnlyReplica) {
		return http.StatusBadRequest, err.Error()
	}
	msg := err.Error()
	if st, isReplica := s.replica(); isReplica {
		msg += adminapi.ManagedOn(st.PrimaryAddr)
	}
	return http.StatusConflict, msg
}

// postDHCPReserve pins the address a device already has, through the same
// promote-to-service path the Discovered screen uses.
func (s *Server) postDHCPReserve(w http.ResponseWriter, r *http.Request) {
	if err := s.promoteLease(r.PostFormValue("ip")); err != nil {
		v, _ := s.liveSettings()
		s.renderDHCP(w, r, http.StatusBadRequest, dhcpFormOf(v), err.Error())
		return
	}
	http.Redirect(w, r, "/dhcp", http.StatusSeeOther)
}
