package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
