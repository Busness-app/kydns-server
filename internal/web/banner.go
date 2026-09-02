package web

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/Busness-app/kydns-server/internal/dnsserver"
	"github.com/Busness-app/kydns-server/internal/settings"
	"github.com/Busness-app/kydns-server/internal/store"
)

// Banner is a dashboard notice. It is not dismissible by design: each one
// clears itself once the underlying condition goes away.
type Banner struct {
	Title string
	Body  string
	Fix   string
}

var cgnatPrefix = netip.MustParsePrefix(settings.TailscaleCGNAT)

// bannerFix is the one actionable instruction, shared by both conditions. The
// setting applies as soon as it is saved, so there is no restart to mention.
const bannerFix = "If you use Tailscale, turn on allow_tailscale under Settings, Server settings."

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
				s.CGNAT, settings.TailscaleCGNAT),
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

// UpstreamsDownBanner fires when every upstream is failing, which means
// nothing outside the private zone resolves at all. Without it an
// all-encrypted list with every entry timing out renders exactly like a
// healthy system, and the operator is pushed away from the screen that has
// the answer.
func UpstreamsDownBanner(statuses []dnsserver.UpstreamStatus) *Banner {
	if len(statuses) == 0 {
		return nil
	}
	reasons := make([]string, 0, len(statuses))
	for _, s := range statuses {
		if s.LastError == "" {
			return nil
		}
		reasons = append(reasons, s.Spec+": "+s.LastError)
	}
	return &Banner{
		Title: "No upstream is answering.",
		Body: fmt.Sprintf(
			"Every upstream failed, so nothing outside your private zone resolves. %s.",
			strings.Join(reasons, "; ")),
		Fix: "Encrypted upstreams need outbound TCP port 853 for tls:// and 443 for https://; " +
			"a firewall blocking those is the usual cause. If they cannot be opened, adding a " +
			"udp:// entry to dns.upstreams and restarting KyDNS restores resolution, at the cost " +
			"of authentication on every answer it serves.",
	}
}

const staleBannerTitle = "This replica is out of date."

// ReplicaStaleBanner fires on the puller's own staleness verdict, so the
// threshold is decided in one place. A replica that quietly stopped following
// its primary renders exactly like a healthy one, and the operator would go on
// trusting what the screen says.
func ReplicaStaleBanner(st ReplicaStatus, now time.Time) *Banner {
	if st.Role != roleReplica || !st.Stale {
		return nil
	}
	when := "has never completed"
	if st.LastSyncUnix != 0 {
		when = "was " + shortDuration(now.Sub(time.Unix(st.LastSyncUnix, 0))) + " ago"
	}
	b := &Banner{
		Title: staleBannerTitle,
		Body: fmt.Sprintf("The last sync with %s %s. What this page shows may already have been replaced on the primary.",
			st.managedBy(), when),
		Fix: "Check that " + st.managedBy() + " is reachable from this node, then look at its replication log.",
	}
	// A primary that refused this node is reachable, and telling the operator to
	// check the network hides the one sentence that says what to do instead.
	if st.LastError != "" {
		b.Body += " The last attempt failed: " + st.LastError + "."
		b.Fix = "That is what the attempt reported, not a network failure. " +
			"If this node was removed on " + st.managedBy() + ", pair it again from the Replication screen."
	}
	return b
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
