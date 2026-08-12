package web

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/yoshiofthewire/kydns-server/internal/config"
	"github.com/yoshiofthewire/kydns-server/internal/dnsserver"
	"github.com/yoshiofthewire/kydns-server/internal/store"
)

// Banner is a dashboard notice. It is not dismissible by design: each one
// clears itself once the underlying condition goes away.
type Banner struct {
	Title string
	Body  string
	Fix   string
}

var cgnatPrefix = netip.MustParsePrefix(config.TailscaleCGNAT)

// bannerFix is the one actionable instruction, shared by both conditions.
const bannerFix = "If you use Tailscale, set allow_tailscale: true in the config file and restart KyDNS."

// TailscaleBanner returns a notice when Tailscale clients cannot reach KyDNS,
// or nil when there is nothing to report.
//
// A closed default is only safe if its failure mode is loud. Two conditions
// fire it:
//
//  1. a query from the CGNAT range was refused inside the window, or
//  2. a view holds CGNAT subnets while allow_tailscale is off, so that view
//     can never match — this catches the operator who just configured a
//     tailnet view, before any client has even tried.
func TailscaleBanner(acl *dnsserver.ACL, views []store.View, allowTailscale bool, window time.Duration) *Banner {
	if allowTailscale {
		return nil
	}
	if acl != nil && acl.RecentCGNATRefusal(window) {
		s := acl.Stats()
		return &Banner{
			Title: "Tailscale clients are being refused.",
			Body: fmt.Sprintf(
				"%d queries from %s were refused. Those clients cannot resolve any name from KyDNS.",
				s.CGNAT, config.TailscaleCGNAT),
			Fix: bannerFix,
		}
	}
	if names := unreachableViews(views, allowTailscale); len(names) > 0 {
		return &Banner{
			Title: "A view can never match.",
			Body: fmt.Sprintf(
				"The view %s covers Tailscale addresses, but the query ACL refuses that range, so those clients are rejected before the view is considered.",
				strings.Join(names, ", ")),
			Fix: bannerFix,
		}
	}
	return nil
}

// PlaintextUpstreamBanner fires when any upstream is unencrypted. Encryption is
// the default, so a udp:// entry is always something someone chose, and the
// operator looking at this screen may not be the one who chose it.
func PlaintextUpstreamBanner(statuses []dnsserver.UpstreamStatus) *Banner {
	var names []string
	for _, s := range statuses {
		if !s.Secure {
			names = append(names, s.Spec)
		}
	}
	if len(names) == 0 {
		return nil
	}
	return &Banner{
		Title: "Some upstream queries are unencrypted.",
		Body: fmt.Sprintf(
			"Plain DNS is used for %s. Anyone on the network path can read and forge those answers, so KyDNS clears the authenticated-data flag on everything they return.",
			strings.Join(names, ", ")),
		Fix: "Replace them with tls:// or https:// entries in dns.upstreams and restart KyDNS.",
	}
}

// unreachableViews names the views whose subnets the ACL rejects outright.
// The settings screen reuses this to flag each row inline.
func unreachableViews(views []store.View, allowTailscale bool) []string {
	if allowTailscale {
		return nil
	}
	var names []string
	for _, v := range views {
		for _, c := range v.Subnets {
			if p, err := netip.ParsePrefix(c); err == nil && cgnatPrefix.Overlaps(p) {
				names = append(names, v.Name)
				break
			}
		}
	}
	return names
}
