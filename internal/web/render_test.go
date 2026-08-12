package web

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func static(t *testing.T, srv *Server, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	srv.StaticHandler().ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
	return rec
}

func TestStaticServesStylesheet(t *testing.T) {
	_, srv := newWeb(t)
	rec := static(t, srv, "/static/app.css")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /static/app.css = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "--accent") {
		t.Error("app.css does not build on the existing design tokens")
	}
}

// A page that links a favicon the binary does not embed shows a broken icon in
// every tab, so the link and the file are checked together.
func TestFaviconIsLinkedAndEmbedded(t *testing.T) {
	_, srv := newWeb(t)

	rec := static(t, srv, "/static/favicon.svg")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /static/favicon.svg = %d, want the icon to be embedded", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "#4deeea") {
		t.Error("favicon does not use the --accent color the rest of the UI uses")
	}

	// /setup renders through base.html with no session, which is where the
	// link lives, so every screen inherits it.
	h, _ := newWeb(t)
	if body := page(t, h, "/setup", nil); !strings.Contains(body, `href="/static/favicon.svg"`) {
		t.Error("base.html does not link the favicon")
	}
}

// The marketing stylesheet shipped with @font-face paths pointing at
// ../assets/fonts, but the fonts live elsewhere. The embedded copy must be
// fixed, and the referenced files must actually be present.
func TestEmbeddedFontPathsResolve(t *testing.T) {
	_, srv := newWeb(t)

	rec := static(t, srv, "/static/styles.css")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /static/styles.css = %d", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "../assets/fonts") {
		t.Error("embedded styles.css still points at ../assets/fonts")
	}
	for _, want := range []string{
		"/static/fonts/Space_Grotesk/SpaceGrotesk-VariableFont_wght.ttf",
		"/static/fonts/IBM_Plex_Mono/IBMPlexMono-Regular.ttf",
		"/static/fonts/IBM_Plex_Mono/IBMPlexMono-Medium.ttf",
		"/static/fonts/IBM_Plex_Mono/IBMPlexMono-SemiBold.ttf",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("styles.css does not reference %s", want)
		}
		if got := static(t, srv, want); got.Code != http.StatusOK {
			t.Errorf("GET %s = %d, want the font to be embedded", want, got.Code)
		}
	}
}

func TestRenderIncludesNavAndAssets(t *testing.T) {
	h, _ := newWeb(t)
	setupAndLogin(t, h)
	c := loginCookie(t, h)

	rec := get(t, h, "/", c)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET / = %d: %s", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	for _, want := range []string{
		`href="/services"`, `href="/records"`, `href="/settings"`,
		"/static/app.css", "/static/styles.css",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("rendered page missing %q", want)
		}
	}
}

// The AGPL obliges us to tell the operator what they are running and to hand
// them the license, so the nav footer, the About popover and the embedded
// license text are checked together.
func TestNavFooterOpensLicense(t *testing.T) {
	h, srv := newWeb(t)
	setupAndLogin(t, h)
	c := loginCookie(t, h)

	body := get(t, h, "/", c).Body.String()
	for _, want := range []string{
		`popovertarget="about"`,
		"Licensed under AGPL v3",
		"KyDNS <span class=\"badge accent\">v" + Version,
		"Developed by Busnes.app",
		`src="/license"`,
		"&copy; " + strconv.Itoa(time.Now().Year()),
	} {
		if !strings.Contains(body, want) {
			t.Errorf("rendered page missing %q", want)
		}
	}

	// The popover frames /license, which must carry the site chrome rather
	// than a bare browser text frame, and must not need a session.
	lic := get(t, h, "/license", nil)
	if lic.Code != http.StatusOK {
		t.Fatalf("GET /license = %d", lic.Code)
	}
	for _, want := range []string{"GNU AFFERO GENERAL PUBLIC LICENSE", "/static/app.css", `class="license-body"`} {
		if !strings.Contains(lic.Body.String(), want) {
			t.Errorf("/license missing %q", want)
		}
	}

	rec := static(t, srv, "/static/agpl-3.0.txt")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /static/agpl-3.0.txt = %d, want the license to be embedded", rec.Code)
	}
	// A display rule outside :popover-open beats the UA rule that hides a
	// closed popover, which pins the panel over every page with no way to
	// close it.
	css := static(t, srv, "/static/app.css").Body.String()
	if !strings.Contains(css, ".license-window:popover-open { display: flex;") {
		t.Error("the license popover is not shown via :popover-open")
	}
	_, rest, _ := strings.Cut(css, ".license-window {")
	block, _, _ := strings.Cut(rest, "}")
	if strings.Contains(block, "display") {
		t.Errorf(".license-window sets display while closed, so it never hides:\n%s", block)
	}

	// The served copy is what the operator reads, so it must stay identical to
	// the license the project ships under.
	want, err := os.ReadFile("../../LICENSE")
	if err != nil {
		t.Fatalf("read LICENSE: %v", err)
	}
	if rec.Body.String() != string(want) {
		t.Error("embedded agpl-3.0.txt has drifted from LICENSE")
	}
}

// Every full page carries the session's CSRF token, so its forms can post.
func TestRenderIncludesCSRFToken(t *testing.T) {
	h, srv := newWeb(t)
	setupAndLogin(t, h)
	c := loginCookie(t, h)
	sess, ok := srv.o.Sessions.Get(c.Value)
	if !ok {
		t.Fatal("no session")
	}
	if !strings.Contains(get(t, h, "/", c).Body.String(), sess.CSRF) {
		t.Error("rendered page does not carry the session CSRF token")
	}
}

// The active nav item is marked, so the operator can tell where they are.
func TestRenderMarksCurrentNav(t *testing.T) {
	h, _ := newWeb(t)
	setupAndLogin(t, h)
	c := loginCookie(t, h)
	body := get(t, h, "/services", c).Body.String()
	if !strings.Contains(body, `href="/services" aria-current="page"`) {
		t.Errorf("current nav item not marked:\n%s", body)
	}
}

// Templates must escape interpolated values. Operator input reaches the page
// unfiltered otherwise.
func TestTemplatesEscapeHTML(t *testing.T) {
	_, srv := newWeb(t)
	rec := httptest.NewRecorder()
	srv.renderBare(rec, "login.html", map[string]any{
		"Title": "Sign in", "Error": `<script>alert(1)</script>`,
	})
	if strings.Contains(rec.Body.String(), "<script>alert(1)</script>") {
		t.Errorf("template emitted unescaped HTML:\n%s", rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "&lt;script&gt;") {
		t.Errorf("expected escaped output:\n%s", rec.Body)
	}
}

// An unknown page name is a 500, not a blank 200 that looks like success.
func TestRenderUnknownPageFails(t *testing.T) {
	h, _ := newWeb(t)
	setupAndLogin(t, h)
	c := loginCookie(t, h)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(c)
	_, srv := newWeb(t)
	srv.render(rec, req, "nope.html", map[string]any{"Title": "x"})
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("render of an unknown page = %d, want 500", rec.Code)
	}
}
