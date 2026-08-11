package web

import (
	"bytes"
	"embed"
	"html/template"
	"net/http"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

// bareTemplates are the pages shown before a session exists: no navigation,
// no CSRF token. Parsed once at init rather than per request.
var bareTemplates = template.Must(template.ParseFS(templateFS,
	"templates/base.html", "templates/login.html", "templates/setup.html"))

// pageTemplates hold the full-chrome screens, each parsed with base + layout.
var pageTemplates = map[string]*template.Template{}

// registerPage parses one full-chrome page. Screens call this from init.
func registerPage(name string) {
	pageTemplates[name] = template.Must(template.ParseFS(templateFS,
		"templates/base.html", "templates/layout.html", "templates/"+name))
}

// renderBare draws a page with no navigation: setup and login, where there is
// no session yet.
func (s *Server) renderBare(w http.ResponseWriter, page string, data map[string]any) {
	t, err := bareTemplates.Clone()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if _, err := t.ParseFS(templateFS, "templates/"+page); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.execute(w, t, data)
}

// render draws a full page with navigation and the session's CSRF token.
func (s *Server) render(w http.ResponseWriter, r *http.Request, page string, data map[string]any) {
	t, ok := pageTemplates[page]
	if !ok {
		s.o.Logger.Error("render: unknown page", "page", page)
		http.Error(w, "unknown page "+page, http.StatusInternalServerError)
		return
	}
	if data == nil {
		data = map[string]any{}
	}
	if sess, ok := s.session(r); ok {
		data["CSRF"] = sess.CSRF
	}
	if _, ok := data["Nav"]; !ok {
		data["Nav"] = ""
	}
	s.execute(w, t, data)
}

// execute renders to a buffer first, so a template error becomes a 500 rather
// than a half-written page.
func (s *Server) execute(w http.ResponseWriter, t *template.Template, data map[string]any) {
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "base", data); err != nil {
		s.o.Logger.Error("render", "error", err)
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(buf.Bytes())
}

// StaticHandler serves the embedded stylesheet, app CSS, and fonts. Embedding
// keeps the binary self-contained: there is no asset directory to deploy.
func (s *Server) StaticHandler() http.Handler {
	return http.FileServer(http.FS(staticFS))
}
