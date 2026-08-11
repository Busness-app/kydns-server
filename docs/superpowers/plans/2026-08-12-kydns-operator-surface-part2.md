# KyDNS Operator Surface Implementation Plan — Part 2 (Tasks 18–21)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax for tracking.

**Continues:** Plan 2 Part 1 (Tasks 14–17). Read Plan 1's **Global Constraints**.

**Goal of this part:** the screens. Dashboard with the Tailscale refusal banner, Services with per-view addresses, Records, and Settings with the views editor. Ends with `serve` mounting the web server alongside the API.

**Note on the Discovered screen:** it belongs to Plan 3, which owns lease data. Its nav link exists from Task 17 and 404s until then. Task 21 adds a placeholder page so the link is never broken.

---

### Task 18: Dashboard and the refusal banner

**Files:**
- Create: `internal/web/dashboard.go`, `internal/web/banner.go`, `internal/web/templates/dashboard.html` (replaces the Task 17 placeholder)
- Test: `internal/web/banner_test.go`, `internal/web/dashboard_test.go`

**Interfaces:**
- Consumes: `dnsserver.ACL`, `dnsserver.Cache`, `registry.Registry`, `config.Config`.
- Produces:
  - `type Banner struct { Title, Body, Fix string }`
  - `func TailscaleBanner(acl *dnsserver.ACL, views []store.View, allowTailscale bool, window time.Duration) *Banner` — nil when neither condition holds
  - `func (s *Server) getDashboard(w http.ResponseWriter, r *http.Request)`
  - `Options` gains `AllowTailscale bool` and `Upstreams []string`

- [ ] **Step 1: Write the failing test**

```go
// internal/web/banner_test.go
package web

import (
	"net/netip"
	"testing"
	"time"

	"github.com/yoshiofthewire/kydns-server/internal/dnsserver"
	"github.com/yoshiofthewire/kydns-server/internal/store"
)

func tailnetViews() []store.View {
	return []store.View{{Name: "tailnet", Subnets: []string{"100.64.0.0/10"}}}
}

// Nothing to report: no refusals, no CGNAT view.
func TestNoBannerWhenQuiet(t *testing.T) {
	acl := dnsserver.NewACL([]netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")})
	if b := TailscaleBanner(acl, nil, false, time.Hour); b != nil {
		t.Errorf("TailscaleBanner() = %+v, want nil", b)
	}
}

// Condition 1: a tailnet client was actually refused.
func TestBannerOnRecentCGNATRefusal(t *testing.T) {
	acl := dnsserver.NewACL([]netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")})
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
	acl := dnsserver.NewACL([]netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")})
	b := TailscaleBanner(acl, tailnetViews(), false, time.Hour)
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
```

Add `"strings"` to the test imports.

```go
// internal/web/dashboard_test.go
package web

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func TestDashboardShowsRefusalCounters(t *testing.T) {
	h, srv := newWeb(t)
	setupAndLogin(t, h)
	srv.o.ACL.Allow(netip.MustParseAddr("8.8.8.8"))
	srv.o.ACL.Allow(netip.MustParseAddr("100.64.0.1"))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(loginCookie(t, h))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET / = %d: %s", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Refused") {
		t.Error("dashboard does not show refusal counters")
	}
	if !strings.Contains(body, "banner") {
		t.Error("dashboard did not render the banner after a CGNAT refusal")
	}
}

func TestDashboardWithoutBanner(t *testing.T) {
	h, srv := newWeb(t)
	setupAndLogin(t, h)
	srv.o.AllowTailscale = true

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(loginCookie(t, h))
	h.ServeHTTP(rec, req)
	if strings.Contains(rec.Body.String(), `class="banner"`) {
		t.Error("banner rendered when there was nothing to report")
	}
}
```

Update `newWeb` in `auth_test.go` to supply an ACL and cache:

```go
	srv := New(Options{
		Store:      st,
		Registry:   registry.New(st, "home.arpa.", func() error { return nil }),
		Sessions:   auth.NewSessions(time.Hour, 12*time.Hour),
		Backoff:    auth.NewBackoff(),
		ACL:        dnsserver.NewACL([]netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")}),
		Cache:      dnsserver.NewCache(100, 5, 3600, 300),
		Upstreams:  []string{"1.1.1.1:53"},
		SetupToken: "setup-me",
	})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/web/ -run 'TestBanner|TestNoBanner|TestDashboard' -v`
Expected: FAIL — `undefined: TailscaleBanner`.

- [ ] **Step 3: Write minimal implementation**

```go
// internal/web/banner.go
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
	const fix = "If you use Tailscale, set allow_tailscale: true in the config file and restart KyDNS."

	if acl != nil && acl.RecentCGNATRefusal(window) {
		s := acl.Stats()
		return &Banner{
			Title: "Tailscale clients are being refused.",
			Body: fmt.Sprintf(
				"%d queries from %s were refused. Those clients cannot resolve any name from KyDNS.",
				s.CGNAT, config.TailscaleCGNAT),
			Fix: fix,
		}
	}

	var unreachable []string
	for _, v := range views {
		for _, c := range v.Subnets {
			p, err := netip.ParsePrefix(c)
			if err == nil && cgnatPrefix.Overlaps(p) {
				unreachable = append(unreachable, v.Name)
				break
			}
		}
	}
	if len(unreachable) > 0 {
		return &Banner{
			Title: "A view can never match.",
			Body: fmt.Sprintf(
				"The view %s covers Tailscale addresses, but the query ACL refuses that range, so those clients are rejected before the view is considered.",
				strings.Join(unreachable, ", ")),
			Fix: fix,
		}
	}
	return nil
}
```

```go
// internal/web/dashboard.go
package web

import (
	"net/http"
	"time"
)

// bannerWindow is how far back a CGNAT refusal still counts as current.
const bannerWindow = time.Hour

func (s *Server) getDashboard(w http.ResponseWriter, r *http.Request) {
	views, err := s.o.Registry.Views()
	if err != nil {
		s.render(w, r, "dashboard.html", map[string]any{
			"Title": "Dashboard", "Nav": "dashboard", "Error": err.Error(),
		})
		return
	}
	svcs, _ := s.o.Registry.Services()
	recs, _ := s.o.Registry.Records()

	data := map[string]any{
		"Title": "Dashboard", "Nav": "dashboard",
		"Banner":    TailscaleBanner(s.o.ACL, views, s.o.AllowTailscale, bannerWindow),
		"Services":  len(svcs),
		"Records":   len(recs),
		"Views":     len(views),
		"Upstreams": s.o.Upstreams,
	}
	if s.o.ACL != nil {
		st := s.o.ACL.Stats()
		data["RefusedTotal"] = st.Total
		data["RefusedCGNAT"] = st.CGNAT
	}
	if s.o.Cache != nil {
		data["CacheEntries"] = s.o.Cache.Len()
	}
	s.render(w, r, "dashboard.html", data)
}
```

```html
<!-- internal/web/templates/dashboard.html — replaces the Task 17 placeholder -->
{{define "page"}}
{{with .Banner}}
<div class="banner">
  <strong>{{.Title}}</strong>
  <p>{{.Body}}</p>
  <p>{{.Fix}}</p>
</div>
{{end}}

<div class="card stat-row">
  <div class="stat"><div class="value">{{.Services}}</div><div class="label">Services</div></div>
  <div class="stat"><div class="value">{{.Records}}</div><div class="label">Records</div></div>
  <div class="stat"><div class="value">{{.Views}}</div><div class="label">Views</div></div>
  <div class="stat"><div class="value">{{.CacheEntries}}</div><div class="label">Cached</div></div>
</div>

<div class="card">
  <table class="grid">
    <tr><th>Metric</th><th>Value</th></tr>
    <tr><td>Refused queries (total)</td><td>{{.RefusedTotal}}</td></tr>
    <tr><td>Refused from Tailscale range</td><td>{{.RefusedCGNAT}}</td></tr>
    <tr><td>Upstreams</td><td>{{range .Upstreams}}<span class="badge">{{.}}</span> {{end}}</td></tr>
  </table>
</div>
{{end}}
```

Add the fields to `Options` in `middleware.go`:

```go
	AllowTailscale bool
	Upstreams      []string
```

Wire the route in `pages.go`:

```go
	mux.HandleFunc("GET /", s.requireSession(s.getDashboard))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/web/ -v`
Expected: PASS, including both banner conditions and the clear-after-window case.

- [ ] **Step 5: Commit**

```bash
git add internal/web
git commit -m "Add dashboard with ACL refusal counters and Tailscale banner

The banner fires on a recent CGNAT refusal or on a view that can never
match because the ACL rejects its range. The second condition catches
the operator who just configured a tailnet view, before any client has
tried. Not dismissible: both conditions clear themselves.

AI-assisted contribution (agentic). Verified with: go test ./internal/web/"
```

---

### Task 19: Services screen

**Files:**
- Create: `internal/web/services.go`, `internal/web/templates/services.html`
- Test: `internal/web/services_test.go`

**Interfaces:**
- Consumes: `registry.Registry`, `render`, `requireCSRF`.
- Produces: `getServices`, `postServiceNew`, `postServiceDelete` handlers.

- [ ] **Step 1: Write the failing test**

```go
// internal/web/services_test.go
package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func loggedIn(t *testing.T) (http.Handler, *Server, *http.Cookie, string) {
	t.Helper()
	h, srv := newWeb(t)
	setupAndLogin(t, h)
	c := loginCookie(t, h)
	sess, ok := srv.o.Sessions.Get(c.Value)
	if !ok {
		t.Fatal("no session")
	}
	return h, srv, c, sess.CSRF
}

func page(t *testing.T, h http.Handler, path string, c *http.Cookie) string {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", path, nil)
	req.AddCookie(c)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d: %s", path, rec.Code, rec.Body)
	}
	return rec.Body.String()
}

func TestServiceCreateAppearsInTable(t *testing.T) {
	h, _, c, csrf := loggedIn(t)
	rec := postForm(t, h, "/services/new", url.Values{
		"name": {"kypost"}, "address": {"192.168.1.20"}, "view": {""},
		"aliases": {"webmail"}, "csrf_token": {csrf},
	}, c)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("create = %d: %s", rec.Code, rec.Body)
	}
	body := page(t, h, "/services", c)
	for _, want := range []string{"kypost", "192.168.1.20", "webmail"} {
		if !strings.Contains(body, want) {
			t.Errorf("services page missing %q", want)
		}
	}
}

// Untagged addresses must read as "all views", never as a blank cell — blank
// reads as broken rather than as everywhere.
func TestUntaggedAddressLabelledAllViews(t *testing.T) {
	h, _, c, csrf := loggedIn(t)
	postForm(t, h, "/services/new", url.Values{
		"name": {"nas"}, "address": {"192.168.1.30"}, "csrf_token": {csrf},
	}, c)
	if !strings.Contains(page(t, h, "/services", c), "all views") {
		t.Error("untagged address is not labelled \"all views\"")
	}
}

func TestServiceCreateWithViewTag(t *testing.T) {
	h, _, c, csrf := loggedIn(t)
	postForm(t, h, "/settings/views/new", url.Values{
		"name": {"tailnet"}, "subnets": {"100.64.0.0/10"}, "csrf_token": {csrf},
	}, c)
	rec := postForm(t, h, "/services/new", url.Values{
		"name": {"kypost"}, "address": {"100.101.102.103"}, "view": {"tailnet"},
		"csrf_token": {csrf},
	}, c)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("create = %d: %s", rec.Code, rec.Body)
	}
	if !strings.Contains(page(t, h, "/services", c), "tailnet") {
		t.Error("view tag not shown on the services page")
	}
}

// A validation failure must re-render the form with the field-level message,
// not a bare 500 or a silent redirect.
func TestServiceValidationErrorRendersInline(t *testing.T) {
	h, _, c, csrf := loggedIn(t)
	rec := postForm(t, h, "/services/new", url.Values{
		"name": {"bad_name"}, "address": {"192.168.1.20"}, "csrf_token": {csrf},
	}, c)
	if rec.Code == http.StatusSeeOther {
		t.Fatal("invalid service was accepted")
	}
	if rec.Code >= 500 {
		t.Fatalf("validation failure returned %d, want a re-rendered form", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "name") {
		t.Errorf("error page does not name the offending field:\n%s", rec.Body)
	}
}

func TestServiceDelete(t *testing.T) {
	h, srv, c, csrf := loggedIn(t)
	postForm(t, h, "/services/new", url.Values{
		"name": {"gone"}, "address": {"192.168.1.40"}, "csrf_token": {csrf},
	}, c)
	svcs, err := srv.o.Registry.Services()
	if err != nil || len(svcs) != 1 {
		t.Fatalf("Services() = %v, %v", svcs, err)
	}
	rec := postForm(t, h, "/services/delete", url.Values{
		"id": {itoa(svcs[0].ID)}, "csrf_token": {csrf},
	}, c)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("delete = %d: %s", rec.Code, rec.Body)
	}
	if strings.Contains(page(t, h, "/services", c), "gone") {
		t.Error("deleted service still on the page")
	}
}

// The view dropdown must offer every configured view plus the untagged option.
func TestServiceFormListsViews(t *testing.T) {
	h, _, c, csrf := loggedIn(t)
	postForm(t, h, "/settings/views/new", url.Values{
		"name": {"tailnet"}, "subnets": {"100.64.0.0/10"}, "csrf_token": {csrf},
	}, c)
	body := page(t, h, "/services", c)
	if !strings.Contains(body, `value="tailnet"`) {
		t.Error("view dropdown does not offer tailnet")
	}
	if !strings.Contains(body, "All views") {
		t.Error("view dropdown does not offer the untagged option")
	}
}
```

Add to `auth_test.go`:

```go
func itoa(i int64) string { return strconv.FormatInt(i, 10) }
```

with `"strconv"` imported.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/web/ -run TestService -v`
Expected: FAIL — no `/services/new` route.

- [ ] **Step 3: Write minimal implementation**

```go
// internal/web/services.go
package web

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/yoshiofthewire/kydns-server/internal/store"
)

type serviceRow struct {
	ID        int64
	Name      string
	Addresses []addressRow
	Aliases   string
}

type addressRow struct {
	Address string
	View    string // display text, never blank
}

func (s *Server) servicesData(r *http.Request, errMsg string) map[string]any {
	svcs, err := s.o.Registry.Services()
	if err != nil && errMsg == "" {
		errMsg = err.Error()
	}
	rows := make([]serviceRow, 0, len(svcs))
	for _, svc := range svcs {
		row := serviceRow{ID: svc.ID, Name: svc.Name, Aliases: strings.Join(svc.Aliases, ", ")}
		for _, a := range svc.Addresses {
			view := a.View
			if view == "" {
				// Blank reads as broken; "all views" reads as everywhere.
				view = "all views"
			}
			row.Addresses = append(row.Addresses, addressRow{Address: a.Address, View: view})
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
	s.render(w, r, "services.html", s.servicesData(r, ""))
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
	if a := strings.TrimSpace(r.PostFormValue("aliases")); a != "" {
		for _, al := range strings.Split(a, ",") {
			svc.Aliases = append(svc.Aliases, strings.TrimSpace(al))
		}
	}
	if _, err := s.o.Registry.PutService(svc); err != nil {
		// Re-render with the field-level message rather than a bare error page.
		w.WriteHeader(http.StatusBadRequest)
		s.render(w, r, "services.html", s.servicesData(r, err.Error()))
		return
	}
	http.Redirect(w, r, "/services", http.StatusSeeOther)
}

func (s *Server) postServiceDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PostFormValue("id"), 10, 64)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		s.render(w, r, "services.html", s.servicesData(r, "invalid service id"))
		return
	}
	if err := s.o.Registry.DeleteService(id); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		s.render(w, r, "services.html", s.servicesData(r, err.Error()))
		return
	}
	http.Redirect(w, r, "/services", http.StatusSeeOther)
}
```

```html
<!-- internal/web/templates/services.html -->
{{define "page"}}
<div class="card">
  <table class="grid">
    <tr><th>Name</th><th>Address</th><th>View</th><th>Aliases</th><th></th></tr>
    {{range .Services}}
      {{$svc := .}}
      {{range $i, $a := .Addresses}}
      <tr>
        <td>{{if eq $i 0}}{{$svc.Name}}{{end}}</td>
        <td>{{$a.Address}}</td>
        <td>{{if eq $a.View "all views"}}<span class="muted">all views</span>
            {{else}}<span class="badge accent">{{$a.View}}</span>{{end}}</td>
        <td>{{if eq $i 0}}{{$svc.Aliases}}{{end}}</td>
        <td>{{if eq $i 0}}
          <form method="post" action="/services/delete">
            <input type="hidden" name="csrf_token" value="{{$.CSRF}}">
            <input type="hidden" name="id" value="{{$svc.ID}}">
            <button class="danger" type="submit">Remove</button>
          </form>{{end}}</td>
      </tr>
      {{end}}
    {{else}}
      <tr><td colspan="5" class="muted">No services yet.</td></tr>
    {{end}}
  </table>
</div>

<div class="card">
  <h3>Add a service</h3>
  <form class="stack" method="post" action="/services/new">
    <input type="hidden" name="csrf_token" value="{{.CSRF}}">
    <label for="name">Name</label>
    <input id="name" name="name" type="text" placeholder="kypost">
    <label for="address">Address</label>
    <div class="address-row">
      <input id="address" name="address" type="text" placeholder="192.168.1.20">
      <select name="view" aria-label="View">
        <option value="">All views</option>
        {{range .Views}}<option value="{{.Name}}">{{.Name}}</option>{{end}}
      </select>
    </div>
    <label for="aliases">Aliases (comma separated)</label>
    <input id="aliases" name="aliases" type="text" placeholder="webmail">
    <label for="check_url">Health check URL (optional)</label>
    <input id="check_url" name="check_url" type="text" placeholder="https://kypost.home.arpa/health">
    <button type="submit">Add service</button>
  </form>
  <p class="muted">Add a second address with a view tag to give Tailscale clients a different answer for the same name.</p>
</div>
{{end}}
```

Register and route:

```go
// append to internal/web/pages.go init()
	registerPage("services.html")

// in pageRoutes
	mux.HandleFunc("GET /services", s.requireSession(s.getServices))
	mux.HandleFunc("POST /services/new", s.requireCSRF(s.postServiceNew))
	mux.HandleFunc("POST /services/delete", s.requireCSRF(s.postServiceDelete))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/web/ -v`
Expected: PASS, six service tests.

- [ ] **Step 5: Commit**

```bash
git add internal/web
git commit -m "Add services screen with per-view addresses

Untagged addresses render as \"all views\" rather than an empty cell,
because blank reads as broken instead of as everywhere. Validation
failures re-render the form with the field-level message.

AI-assisted contribution (agentic). Verified with: go test ./internal/web/"
```

---

### Task 20: Records screen

**Files:**
- Create: `internal/web/records.go`, `internal/web/templates/records.html`
- Test: `internal/web/records_test.go`

**Interfaces:**
- Consumes: `registry.Registry`.
- Produces: `getRecords`, `postRecordNew`, `postRecordDelete`.

- [ ] **Step 1: Write the failing test**

```go
// internal/web/records_test.go
package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestRecordCreateAndList(t *testing.T) {
	h, _, c, csrf := loggedIn(t)
	rec := postForm(t, h, "/records/new", url.Values{
		"name": {"printer.home.arpa."}, "type": {"A"}, "value": {"192.168.1.50"},
		"csrf_token": {csrf},
	}, c)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("create = %d: %s", rec.Code, rec.Body)
	}
	body := page(t, h, "/records", c)
	for _, want := range []string{"printer.home.arpa.", "192.168.1.50", "A"} {
		if !strings.Contains(body, want) {
			t.Errorf("records page missing %q", want)
		}
	}
}

func TestRecordTypeDropdownIsLimitedToV1Types(t *testing.T) {
	h, _, c, _ := loggedIn(t)
	body := page(t, h, "/records", c)
	for _, want := range []string{`value="A"`, `value="AAAA"`, `value="CNAME"`, `value="PTR"`} {
		if !strings.Contains(body, want) {
			t.Errorf("type dropdown missing %s", want)
		}
	}
	for _, unwanted := range []string{`value="TXT"`, `value="MX"`, `value="SRV"`} {
		if strings.Contains(body, unwanted) {
			t.Errorf("type dropdown offers unsupported %s", unwanted)
		}
	}
}

func TestRecordRejectsUnsupportedType(t *testing.T) {
	h, _, c, csrf := loggedIn(t)
	rec := postForm(t, h, "/records/new", url.Values{
		"name": {"x.home.arpa."}, "type": {"TXT"}, "value": {"hello"}, "csrf_token": {csrf},
	}, c)
	if rec.Code == http.StatusSeeOther {
		t.Error("TXT record accepted, want rejection")
	}
}

func TestRecordRejectsOutOfZoneName(t *testing.T) {
	h, _, c, csrf := loggedIn(t)
	rec := postForm(t, h, "/records/new", url.Values{
		"name": {"evil.example.com."}, "type": {"A"}, "value": {"192.168.1.1"}, "csrf_token": {csrf},
	}, c)
	if rec.Code == http.StatusSeeOther {
		t.Error("out-of-zone record accepted, want rejection")
	}
}

func TestRecordDelete(t *testing.T) {
	h, srv, c, csrf := loggedIn(t)
	postForm(t, h, "/records/new", url.Values{
		"name": {"temp.home.arpa."}, "type": {"A"}, "value": {"192.168.1.60"}, "csrf_token": {csrf},
	}, c)
	recs, err := srv.o.Registry.Records()
	if err != nil || len(recs) != 1 {
		t.Fatalf("Records() = %v, %v", recs, err)
	}
	if got := postForm(t, h, "/records/delete", url.Values{
		"id": {itoa(recs[0].ID)}, "csrf_token": {csrf},
	}, c); got.Code != http.StatusSeeOther {
		t.Fatalf("delete = %d: %s", got.Code, got.Body)
	}
	if strings.Contains(page(t, h, "/records", c), "temp.home.arpa.") {
		t.Error("deleted record still listed")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/web/ -run TestRecord -v`
Expected: FAIL — no `/records/new` route.

- [ ] **Step 3: Write minimal implementation**

```go
// internal/web/records.go
package web

import (
	"net/http"
	"strconv"

	"github.com/yoshiofthewire/kydns-server/internal/store"
)

// recordTypes mirrors registry.ValidateRecordType. The dropdown offers exactly
// what v1 supports, so an unsupported type is not reachable by accident.
var recordTypes = []string{"A", "AAAA", "CNAME", "PTR"}

func (s *Server) recordsData(errMsg string) map[string]any {
	recs, err := s.o.Registry.Records()
	if err != nil && errMsg == "" {
		errMsg = err.Error()
	}
	views, _ := s.o.Registry.Views()
	return map[string]any{
		"Title": "Records", "Nav": "records",
		"Records": recs, "Views": views, "Types": recordTypes, "Error": errMsg,
	}
}

func (s *Server) getRecords(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "records.html", s.recordsData(""))
}

func (s *Server) postRecordNew(w http.ResponseWriter, r *http.Request) {
	rec := store.Record{
		Name:  r.PostFormValue("name"),
		Type:  r.PostFormValue("type"),
		Value: r.PostFormValue("value"),
		View:  r.PostFormValue("view"),
	}
	if _, err := s.o.Registry.PutRecord(rec); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		s.render(w, r, "records.html", s.recordsData(err.Error()))
		return
	}
	http.Redirect(w, r, "/records", http.StatusSeeOther)
}

func (s *Server) postRecordDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PostFormValue("id"), 10, 64)
	if err == nil {
		err = s.o.Registry.DeleteRecord(id)
	}
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		s.render(w, r, "records.html", s.recordsData(err.Error()))
		return
	}
	http.Redirect(w, r, "/records", http.StatusSeeOther)
}
```

```html
<!-- internal/web/templates/records.html -->
{{define "page"}}
<div class="card">
  <table class="grid">
    <tr><th>Name</th><th>Type</th><th>Value</th><th>View</th><th></th></tr>
    {{range .Records}}
    <tr>
      <td>{{.Name}}</td>
      <td><span class="badge">{{.Type}}</span></td>
      <td>{{.Value}}</td>
      <td>{{if .View}}<span class="badge accent">{{.View}}</span>{{else}}<span class="muted">all views</span>{{end}}</td>
      <td>
        <form method="post" action="/records/delete">
          <input type="hidden" name="csrf_token" value="{{$.CSRF}}">
          <input type="hidden" name="id" value="{{.ID}}">
          <button class="danger" type="submit">Remove</button>
        </form>
      </td>
    </tr>
    {{else}}
      <tr><td colspan="5" class="muted">No manual records. Services cover most needs.</td></tr>
    {{end}}
  </table>
</div>

<div class="card">
  <h3>Add a record</h3>
  <form class="stack" method="post" action="/records/new">
    <input type="hidden" name="csrf_token" value="{{.CSRF}}">
    <label for="rname">Name</label>
    <input id="rname" name="name" type="text" placeholder="printer.home.arpa.">
    <label for="rtype">Type</label>
    <select id="rtype" name="type">
      {{range .Types}}<option value="{{.}}">{{.}}</option>{{end}}
    </select>
    <label for="rvalue">Value</label>
    <input id="rvalue" name="value" type="text" placeholder="192.168.1.50">
    <label for="rview">View</label>
    <select id="rview" name="view">
      <option value="">All views</option>
      {{range .Views}}<option value="{{.Name}}">{{.Name}}</option>{{end}}
    </select>
    <button type="submit">Add record</button>
  </form>
  <p class="muted">A manual record takes precedence over a service or a discovered lease with the same name.</p>
</div>
{{end}}
```

Register and route:

```go
	registerPage("records.html")

	mux.HandleFunc("GET /records", s.requireSession(s.getRecords))
	mux.HandleFunc("POST /records/new", s.requireCSRF(s.postRecordNew))
	mux.HandleFunc("POST /records/delete", s.requireCSRF(s.postRecordDelete))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/web/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/web
git commit -m "Add records screen limited to the v1 record types

The dropdown offers exactly A, AAAA, CNAME, and PTR, so an unsupported
type is not reachable by accident and the server-side check is a
backstop rather than the only guard.

AI-assisted contribution (agentic). Verified with: go test ./internal/web/"
```

---

### Task 21: Settings screen and serve wiring

**Files:**
- Create: `internal/web/settings.go`, `internal/web/templates/settings.html`, `internal/web/templates/discovered.html`
- Modify: `internal/app/serve.go`
- Test: `internal/web/settings_test.go`, `internal/app/web_test.go`

**Interfaces:**
- Consumes: everything above, plus `app.Serve`.
- Produces: `getSettings`, `postViewNew`, `postViewDelete`, `postTokenNew`, `postTokenDelete`, `postCacheFlush`, `getExport`, `postImport`; `Serve` mounting the web server.

- [ ] **Step 1: Write the failing test**

```go
// internal/web/settings_test.go
package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestViewCreateAndList(t *testing.T) {
	h, _, c, csrf := loggedIn(t)
	rec := postForm(t, h, "/settings/views/new", url.Values{
		"name": {"tailnet"}, "subnets": {"100.64.0.0/10"}, "csrf_token": {csrf},
	}, c)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("create view = %d: %s", rec.Code, rec.Body)
	}
	body := page(t, h, "/settings", c)
	if !strings.Contains(body, "tailnet") || !strings.Contains(body, "100.64.0.0/10") {
		t.Errorf("settings page missing the view:\n%s", body)
	}
}

// Condition 2 of the banner, rendered inline where the operator is standing.
func TestUnreachableViewFlaggedInline(t *testing.T) {
	h, srv, c, csrf := loggedIn(t)
	srv.o.AllowTailscale = false
	postForm(t, h, "/settings/views/new", url.Values{
		"name": {"tailnet"}, "subnets": {"100.64.0.0/10"}, "csrf_token": {csrf},
	}, c)
	body := page(t, h, "/settings", c)
	if !strings.Contains(strings.ToLower(body), "unreachable") {
		t.Errorf("CGNAT view not flagged as unreachable:\n%s", body)
	}
}

func TestReachableViewNotFlagged(t *testing.T) {
	h, srv, c, csrf := loggedIn(t)
	srv.o.AllowTailscale = true
	postForm(t, h, "/settings/views/new", url.Values{
		"name": {"tailnet"}, "subnets": {"100.64.0.0/10"}, "csrf_token": {csrf},
	}, c)
	if strings.Contains(strings.ToLower(page(t, h, "/settings", c)), "unreachable") {
		t.Error("view flagged unreachable while allow_tailscale is on")
	}
}

func TestDeleteViewInUseShowsError(t *testing.T) {
	h, _, c, csrf := loggedIn(t)
	postForm(t, h, "/settings/views/new", url.Values{
		"name": {"tailnet"}, "subnets": {"100.64.0.0/10"}, "csrf_token": {csrf},
	}, c)
	postForm(t, h, "/services/new", url.Values{
		"name": {"kypost"}, "address": {"100.101.102.103"}, "view": {"tailnet"},
		"csrf_token": {csrf},
	}, c)
	rec := postForm(t, h, "/settings/views/delete", url.Values{
		"name": {"tailnet"}, "csrf_token": {csrf},
	}, c)
	if rec.Code == http.StatusSeeOther {
		t.Fatal("deleting an in-use view succeeded")
	}
	if !strings.Contains(strings.ToLower(rec.Body.String()), "referenced") {
		t.Errorf("error does not explain the view is in use:\n%s", rec.Body)
	}
}

// A new token's plaintext is shown exactly once, then never again.
func TestTokenShownOnceThenNever(t *testing.T) {
	h, _, c, csrf := loggedIn(t)
	rec := postForm(t, h, "/settings/tokens/new", url.Values{
		"label": {"laptop"}, "csrf_token": {csrf},
	}, c)
	if rec.Code != http.StatusOK {
		t.Fatalf("create token = %d: %s", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	idx := strings.Index(body, "kydns_")
	if idx < 0 {
		t.Fatal("plaintext token not shown on creation")
	}
	plaintext := body[idx : idx+70]
	if strings.Contains(page(t, h, "/settings", c), plaintext) {
		t.Error("token plaintext still visible on a later page load")
	}
}

func TestExportDownloads(t *testing.T) {
	h, _, c, csrf := loggedIn(t)
	postForm(t, h, "/services/new", url.Values{
		"name": {"kypost"}, "address": {"192.168.1.20"}, "csrf_token": {csrf},
	}, c)
	body := page(t, h, "/settings/export?format=yaml", c)
	if !strings.Contains(body, "kypost") {
		t.Errorf("export missing the service:\n%s", body)
	}
	for _, forbidden := range []string{"password_hash", "argon2", "kydns_"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("export leaked %q", forbidden)
		}
	}
}

func TestCacheFlushButton(t *testing.T) {
	h, srv, c, csrf := loggedIn(t)
	if rec := postForm(t, h, "/settings/cache/flush", url.Values{"csrf_token": {csrf}}, c); rec.Code != http.StatusSeeOther {
		t.Fatalf("flush = %d: %s", rec.Code, rec.Body)
	}
	if srv.o.Cache.Len() != 0 {
		t.Error("cache not flushed")
	}
}

// The Discovered nav link exists from Task 17; it must not 404 before Plan 3.
func TestDiscoveredPlaceholder(t *testing.T) {
	h, _, c, _ := loggedIn(t)
	if !strings.Contains(page(t, h, "/discovered", c), "DHCP") {
		t.Error("discovered placeholder does not explain what will appear here")
	}
}
```

```go
// internal/app/web_test.go
package app

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

// serve must mount the web UI on the admin listener alongside the JSON API.
func TestServeMountsWebUI(t *testing.T) {
	dir := t.TempDir()
	dnsPort, adminPort := freePort(t), freePort(t)
	cfg := filepath.Join(dir, "kydns.yaml")
	body := fmt.Sprintf("data_dir: %s\ndns:\n  listen: \"127.0.0.1:%d\"\nadmin:\n  listen: \"127.0.0.1:%d\"\n",
		dir, dnsPort, adminPort)
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go Serve(ctx, cfg, nil)

	base := fmt.Sprintf("http://127.0.0.1:%d", adminPort)
	waitForHTTP(t, base+"/api/v1/healthz")

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Get(base + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("GET / = %d, want a redirect to /setup", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/setup" {
		t.Errorf("GET / redirected to %q, want /setup", loc)
	}

	// The JSON API must still work: the two transports share one listener.
	resp2, err := client.Get(base + "/api/v1/services")
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Errorf("GET /api/v1/services = %d, want 401", resp2.StatusCode)
	}
}

func TestSetupTokenIsLogged(t *testing.T) {
	dir := t.TempDir()
	dnsPort, adminPort := freePort(t), freePort(t)
	cfg := filepath.Join(dir, "kydns.yaml")
	body := fmt.Sprintf("data_dir: %s\ndns:\n  listen: \"127.0.0.1:%d\"\nadmin:\n  listen: \"127.0.0.1:%d\"\n",
		dir, dnsPort, adminPort)
	os.WriteFile(cfg, []byte(body), 0o600)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go Serve(ctx, cfg, nil)
	waitForHTTP(t, fmt.Sprintf("http://127.0.0.1:%d/api/v1/healthz", adminPort))

	if tok := waitForFile(t, filepath.Join(dir, "setup-token")); len(tok) < 16 {
		t.Errorf("setup token %q is too short", tok)
	}
}
```

Rename Plan 1's `waitForSetupToken` to a general `waitForFile(t, path) string`
and update its Plan 1 caller to pass `filepath.Join(dir, "bootstrap-token")`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/web/ ./internal/app/ -v`
Expected: FAIL — no `/settings` routes, `Serve` does not mount the web UI.

- [ ] **Step 3: Write minimal implementation**

```go
// internal/web/settings.go
package web

import (
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/yoshiofthewire/kydns-server/internal/store"
)

type viewRow struct {
	Name        string
	Subnets     string
	Unreachable bool
	References  int
}

func (s *Server) settingsData(errMsg, newToken string) map[string]any {
	views, err := s.o.Registry.Views()
	if err != nil && errMsg == "" {
		errMsg = err.Error()
	}
	svcs, _ := s.o.Registry.Services()
	recs, _ := s.o.Registry.Records()

	rows := make([]viewRow, 0, len(views))
	for _, v := range views {
		row := viewRow{Name: v.Name, Subnets: strings.Join(v.Subnets, ", ")}
		// Banner condition 2, shown where the operator is already standing.
		if !s.o.AllowTailscale {
			for _, c := range v.Subnets {
				if p, err := netip.ParsePrefix(c); err == nil && cgnatPrefix.Overlaps(p) {
					row.Unreachable = true
					break
				}
			}
		}
		for _, svc := range svcs {
			for _, a := range svc.Addresses {
				if a.View == v.Name {
					row.References++
				}
			}
		}
		for _, r := range recs {
			if r.View == v.Name {
				row.References++
			}
		}
		rows = append(rows, row)
	}

	toks, _ := s.o.Registry.Tokens()
	return map[string]any{
		"Title": "Settings", "Nav": "settings",
		"Views": rows, "Tokens": toks, "NewToken": newToken, "Error": errMsg,
	}
}

func (s *Server) getSettings(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "settings.html", s.settingsData("", ""))
}

func (s *Server) settingsError(w http.ResponseWriter, r *http.Request, err error) {
	w.WriteHeader(http.StatusBadRequest)
	s.render(w, r, "settings.html", s.settingsData(err.Error(), ""))
}

func (s *Server) postViewNew(w http.ResponseWriter, r *http.Request) {
	var subnets []string
	for _, c := range strings.Split(r.PostFormValue("subnets"), ",") {
		if c = strings.TrimSpace(c); c != "" {
			subnets = append(subnets, c)
		}
	}
	if err := s.o.Registry.PutView(store.View{Name: r.PostFormValue("name"), Subnets: subnets}); err != nil {
		s.settingsError(w, r, err)
		return
	}
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

func (s *Server) postViewDelete(w http.ResponseWriter, r *http.Request) {
	if err := s.o.Registry.DeleteView(r.PostFormValue("name")); err != nil {
		s.settingsError(w, r, err)
		return
	}
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

// postTokenNew renders the settings page directly rather than redirecting,
// because the plaintext exists only in this response.
func (s *Server) postTokenNew(w http.ResponseWriter, r *http.Request) {
	plaintext, err := s.o.Registry.CreateToken(r.PostFormValue("label"))
	if err != nil {
		s.settingsError(w, r, err)
		return
	}
	s.render(w, r, "settings.html", s.settingsData("", plaintext))
}

func (s *Server) postTokenDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PostFormValue("id"), 10, 64)
	if err == nil {
		err = s.o.Registry.DeleteToken(id)
	}
	if err != nil {
		s.settingsError(w, r, err)
		return
	}
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

func (s *Server) postCacheFlush(w http.ResponseWriter, r *http.Request) {
	if s.o.Cache != nil {
		s.o.Cache.Flush()
	}
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

func (s *Server) getDiscovered(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "discovered.html", map[string]any{"Title": "Discovered", "Nav": "discovered"})
}
```

Export and import reuse the API's document builder rather than duplicating it.
Add to `internal/adminapi/api.go`:

```go
// Document returns the export document for reuse by the web transport, so the
// two never diverge on what is included.
func (a *API) Document() (any, error) { return a.snapshotDoc() }

// WriteExport writes the export document in the requested format.
func (a *API) WriteExport(w http.ResponseWriter, format string) error {
	doc, err := a.snapshotDoc()
	if err != nil {
		return err
	}
	if format == "json" {
		w.Header().Set("Content-Type", "application/json")
		return json.NewEncoder(w).Encode(doc)
	}
	w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
	return yaml.NewEncoder(w).Encode(doc)
}
```

Add `API *adminapi.API` to web `Options`, then:

```go
// append to internal/web/settings.go
func (s *Server) getExport(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "yaml"
	}
	w.Header().Set("Content-Disposition", "attachment; filename=kydns-export."+format)
	if err := s.o.API.WriteExport(w, format); err != nil {
		s.o.Logger.Error("export", "error", err)
	}
}
```

```html
<!-- internal/web/templates/settings.html -->
{{define "page"}}
{{with .NewToken}}
<div class="banner">
  <strong>Copy this token now.</strong>
  <p>It is shown once and cannot be recovered.</p>
  <p><code>{{.}}</code></p>
</div>
{{end}}

<div class="card">
  <h3>Views</h3>
  <table class="grid">
    <tr><th>Name</th><th>Subnets</th><th>Used by</th><th></th></tr>
    {{range .Views}}
    <tr>
      <td>{{.Name}}{{if .Unreachable}} <span class="badge warn">unreachable</span>{{end}}</td>
      <td>{{.Subnets}}</td>
      <td>{{.References}}</td>
      <td>
        <form method="post" action="/settings/views/delete">
          <input type="hidden" name="csrf_token" value="{{$.CSRF}}">
          <input type="hidden" name="name" value="{{.Name}}">
          <button class="danger" type="submit">Remove</button>
        </form>
      </td>
    </tr>
    {{else}}
      <tr><td colspan="4" class="muted">No views. Every client gets the same answers.</td></tr>
    {{end}}
  </table>
  {{range .Views}}{{if .Unreachable}}
  <p class="error">The view {{.Name}} covers Tailscale addresses, but the query ACL refuses that range.
     Set <code>allow_tailscale: true</code> in the config file and restart KyDNS.</p>
  {{end}}{{end}}
  <form class="stack" method="post" action="/settings/views/new">
    <input type="hidden" name="csrf_token" value="{{.CSRF}}">
    <label for="vname">Name</label>
    <input id="vname" name="name" type="text" placeholder="tailnet">
    <label for="vsubnets">Subnets (comma separated)</label>
    <input id="vsubnets" name="subnets" type="text" placeholder="100.64.0.0/10">
    <button type="submit">Add view</button>
  </form>
</div>

<div class="card">
  <h3>API tokens</h3>
  <table class="grid">
    <tr><th>Label</th><th>Created</th><th>Last used</th><th></th></tr>
    {{range .Tokens}}
    <tr>
      <td>{{.Label}}</td><td>{{.CreatedAt}}</td>
      <td>{{if .LastUsedAt}}{{.LastUsedAt}}{{else}}<span class="muted">never</span>{{end}}</td>
      <td>
        <form method="post" action="/settings/tokens/delete">
          <input type="hidden" name="csrf_token" value="{{$.CSRF}}">
          <input type="hidden" name="id" value="{{.ID}}">
          <button class="danger" type="submit">Revoke</button>
        </form>
      </td>
    </tr>
    {{end}}
  </table>
  <form class="stack" method="post" action="/settings/tokens/new">
    <input type="hidden" name="csrf_token" value="{{.CSRF}}">
    <label for="tlabel">Label</label>
    <input id="tlabel" name="label" type="text" placeholder="laptop">
    <button type="submit">Create token</button>
  </form>
</div>

<div class="card">
  <h3>Backup and maintenance</h3>
  <p><a href="/settings/export?format=yaml">Download YAML export</a> &middot;
     <a href="/settings/export?format=json">Download JSON export</a></p>
  <p class="muted">Exports contain views, services, and records. They never contain passwords or tokens.</p>
  <form method="post" action="/settings/cache/flush">
    <input type="hidden" name="csrf_token" value="{{.CSRF}}">
    <button class="ghost" type="submit">Flush DNS cache</button>
  </form>
</div>
{{end}}
```

```html
<!-- internal/web/templates/discovered.html -->
{{define "page"}}
<div class="card">
  <p class="muted">DHCP lease discovery is not enabled in this build.
     Once configured, leases read from the DHCP server appear here and can be promoted to services.</p>
</div>
{{end}}
```

Register and route:

```go
	registerPage("settings.html")
	registerPage("discovered.html")

	mux.HandleFunc("GET /settings", s.requireSession(s.getSettings))
	mux.HandleFunc("GET /settings/export", s.requireSession(s.getExport))
	mux.HandleFunc("GET /discovered", s.requireSession(s.getDiscovered))
	mux.HandleFunc("POST /settings/views/new", s.requireCSRF(s.postViewNew))
	mux.HandleFunc("POST /settings/views/delete", s.requireCSRF(s.postViewDelete))
	mux.HandleFunc("POST /settings/tokens/new", s.requireCSRF(s.postTokenNew))
	mux.HandleFunc("POST /settings/tokens/delete", s.requireCSRF(s.postTokenDelete))
	mux.HandleFunc("POST /settings/cache/flush", s.requireCSRF(s.postCacheFlush))
```

Now mount the web server in `internal/app/serve.go`. Replace the admin handler
construction:

```go
	api := adminapi.NewAPI(reg, acl, cache)
	mux := http.NewServeMux()
	// The API registers /api/v1/... and the web server registers everything
	// else, so one listener serves both transports.
	apiMux := api.Handler().(*http.ServeMux)
	mux.Handle("/api/v1/", apiMux)

	setupToken, err := ensureSetupToken(st, cfg.DataDir, logger)
	if err != nil {
		return err
	}
	websrv := web.New(web.Options{
		Store: st, Registry: reg, API: api,
		Sessions:       auth.NewSessions(time.Hour, 12*time.Hour),
		Backoff:        auth.NewBackoff(),
		ACL:            acl,
		Cache:          cache,
		AllowTailscale: cfg.DNS.AllowTailscale,
		Upstreams:      cfg.DNS.Upstreams,
		SetupToken:     setupToken,
		Logger:         logger,
	})
	websrv.Routes(mux)

	adminSrv := &http.Server{
		Addr:              cfg.Admin.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
```

```go
// append to internal/app/serve.go

// ensureSetupToken mints the one-time token that gates /setup, unless an admin
// already exists. It is logged and written to the data dir, because the
// operator needs it from a terminal before any UI is reachable.
func ensureSetupToken(st *store.Store, dataDir string, logger *slog.Logger) (string, error) {
	has, err := st.HasAdmin()
	if err != nil {
		return "", err
	}
	if has {
		return "", nil // no admin creation possible, so no token needed
	}
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	token := hex.EncodeToString(buf)
	path := filepath.Join(dataDir, "setup-token")
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		return "", err
	}
	logger.Info("no admin account yet: open the web UI and use this setup token",
		"token", token, "path", path)
	return token, nil
}
```

Add imports to `serve.go`: `crypto/rand`, `encoding/hex`, `net/http`, and the
`auth` and `web` packages.

- [ ] **Step 4: Run the full suite**

Run: `CGO_ENABLED=0 go test ./... -race`
Expected: PASS across every package.

Then a manual pass:

```bash
make build
rm -rf /tmp/kydns && mkdir -p /tmp/kydns
printf 'data_dir: /tmp/kydns\ndns:\n  listen: "127.0.0.1:5353"\nadmin:\n  listen: "127.0.0.1:8053"\n' > /tmp/kydns.yaml
./bin/kydns serve --config /tmp/kydns.yaml
# Read the setup token from the log, open http://127.0.0.1:8053/ and complete setup.
# Add a view "tailnet" for 100.64.0.0/10 and confirm the unreachable badge appears.
```

- [ ] **Step 5: Commit**

```bash
git add internal/web internal/app internal/adminapi
git commit -m "Add settings screen and mount the web UI on the admin listener

The views editor flags a view the ACL can never reach, which is banner
condition 2 rendered where the operator is already standing. A new API
token's plaintext is rendered directly rather than through a redirect,
because it exists only in that one response.

Export reuses the API's document builder so the two transports cannot
diverge on what a backup contains.

AI-assisted contribution (agentic). Verified with: CGO_ENABLED=0 go test ./... -race,
plus a manual setup and view-creation pass against the built binary."
```

---

## Self-Review (Plan 2, Part 2)

**Spec coverage.** Five screens: Dashboard (Task 18), Services (19), Records (20), Settings (21), Discovered placeholder (21, filled by Plan 3). Refusal counters on the dashboard and both banner conditions → Tasks 18 and 21. Untagged shown as "all views" → Task 19. Views editor showing references and flagging unreachable views → Task 21. Tokens shown once → Task 21. Export omitting secrets → Task 21, reusing the API builder.

**Deliberately deferred to Plan 3:** live lease and health tables, and therefore the `fetch`-on-a-timer refresh the spec describes. Both target data that does not exist until Plan 3, so adding the polling now would refresh empty tables.

**Placeholder scan.** The Task 17 `dashboard.html` placeholder is replaced in full by Task 18. `discovered.html` is a real page explaining what will appear, not a stub — Plan 3 replaces its contents.

**Type consistency.** `Options` gains `AllowTailscale`, `Upstreams`, and `API` in Tasks 18 and 21, and every field is set in Task 21's `serve` wiring. `TailscaleBanner(acl, views, allowTailscale, window)` has one signature, called from `getDashboard`. `cgnatPrefix` is declared once in `banner.go` and reused by `settingsData`. `registerPage` from Part 1 Task 17 is called for every page added here.
