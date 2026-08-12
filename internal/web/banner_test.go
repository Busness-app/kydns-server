package web

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/yoshiofthewire/kydns-server/internal/dnsserver"
	"github.com/yoshiofthewire/kydns-server/internal/store"
)

func tailnetViews() []store.View {
	return []store.View{{Name: "tailnet", Subnets: []string{"100.64.0.0/10"}}}
}

func lanOnlyACL() *dnsserver.ACL {
	return dnsserver.NewACL([]netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")})
}

// Nothing to report: no refusals, no CGNAT view.
func TestNoBannerWhenQuiet(t *testing.T) {
	if b := TailscaleBanner(lanOnlyACL(), nil, false, time.Hour); b != nil {
		t.Errorf("TailscaleBanner() = %+v, want nil", b)
	}
}

// Condition 1: a tailnet client was actually refused.
func TestBannerOnRecentCGNATRefusal(t *testing.T) {
	acl := lanOnlyACL()
	acl.Allow(netip.MustParseAddr("100.101.102.103"))

	b := TailscaleBanner(acl, nil, false, time.Hour)
	if b == nil {
		t.Fatal("TailscaleBanner() = nil after a CGNAT refusal")
	}
	if !strings.Contains(b.Fix, "allow_tailscale") {
		t.Errorf("Fix = %q, want the config key named", b.Fix)
	}
	if !strings.Contains(strings.ToLower(b.Fix), "restart") {
		t.Errorf("Fix = %q, want the restart requirement stated", b.Fix)
	}
	if !strings.Contains(b.Body, "1") {
		t.Errorf("Body = %q, want the refusal count", b.Body)
	}
}

// Condition 2: a CGNAT view exists but the flag is off, so it can never match.
// This fires before any client has even tried.
func TestBannerOnUnreachableView(t *testing.T) {
	b := TailscaleBanner(lanOnlyACL(), tailnetViews(), false, time.Hour)
	if b == nil {
		t.Fatal("TailscaleBanner() = nil for a CGNAT view with the flag off")
	}
	if !strings.Contains(b.Body, "tailnet") {
		t.Errorf("Body = %q, want the offending view named", b.Body)
	}
}

// With the flag on, neither condition can hold.
func TestNoBannerWhenFlagIsOn(t *testing.T) {
	acl := dnsserver.NewACL([]netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")})
	if b := TailscaleBanner(acl, tailnetViews(), true, time.Hour); b != nil {
		t.Errorf("TailscaleBanner() = %+v with allow_tailscale on, want nil", b)
	}
}

// The banner clears itself once refusals age out of the window.
func TestBannerClearsAfterWindow(t *testing.T) {
	acl := dnsserver.NewACL(nil)
	acl.Allow(netip.MustParseAddr("100.64.0.1"))
	if TailscaleBanner(acl, nil, false, time.Hour) == nil {
		t.Fatal("banner did not fire")
	}
	if b := TailscaleBanner(acl, nil, false, time.Nanosecond); b != nil {
		t.Error("banner did not clear once the refusal aged out of the window")
	}
}

// A non-CGNAT view is not flagged; only ranges the ACL actually refuses are.
func TestNoBannerForNonCGNATView(t *testing.T) {
	views := []store.View{{Name: "lab", Subnets: []string{"192.168.7.0/24"}}}
	if b := TailscaleBanner(lanOnlyACL(), views, false, time.Hour); b != nil {
		t.Errorf("TailscaleBanner() = %+v for a reachable view, want nil", b)
	}
}

func TestPlaintextUpstreamBanner(t *testing.T) {
	secure := []dnsserver.UpstreamStatus{
		{Spec: "tls://1.1.1.1:853", Secure: true},
		{Spec: "https://9.9.9.9/dns-query", Secure: true},
	}
	if b := PlaintextUpstreamBanner(secure); b != nil {
		t.Errorf("banner = %+v with every upstream encrypted, want nil", b)
	}

	mixed := append(secure, dnsserver.UpstreamStatus{Spec: "udp://192.168.1.1:53"})
	b := PlaintextUpstreamBanner(mixed)
	if b == nil {
		t.Fatal("banner = nil with a plaintext upstream configured")
	}
	if !strings.Contains(b.Body, "udp://192.168.1.1:53") {
		t.Errorf("body %q does not name the plaintext upstream", b.Body)
	}
	if strings.Contains(b.Body, "tls://1.1.1.1:853") {
		t.Errorf("body %q names an encrypted upstream", b.Body)
	}
	if b.Fix == "" {
		t.Error("banner has no fix")
	}
}
