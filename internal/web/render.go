package web

import (
	"html/template"
	"net/http"
)

// ponytail: placeholder rendering until Task 17 embeds real templates. Kept
// html/template so escaping behavior matches the final implementation.
var stubTemplate = template.Must(template.New("stub").Parse(
	`<!doctype html><title>{{.Title}}</title>{{with .Error}}<p class="error">{{.}}</p>{{end}}`))

func (s *Server) renderBare(w http.ResponseWriter, page string, data map[string]any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	stubTemplate.Execute(w, data)
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, page string, data map[string]any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	stubTemplate.Execute(w, data)
}
