package web

import (
	"crypto/subtle"
	"net/http"
	"time"

	"github.com/yoshiofthewire/kydns-server/internal/auth"
)

// registrar is the sliver of *http.ServeMux that registration uses. ServeMux
// cannot be enumerated, so this is what lets a test derive the route table
// from the router rather than hand-listing it.
type registrar interface {
	Handle(pattern string, h http.Handler)
	HandleFunc(pattern string, h func(http.ResponseWriter, *http.Request))
}

// Routes registers the web transport on a mux it shares with the API. The mux
// is not where writes are refused: wrap the whole server handler in WriteGate.
func (s *Server) Routes(mux *http.ServeMux) { s.routes(mux) }

func (s *Server) routes(mux registrar) {
	mux.HandleFunc("GET /setup", s.getSetup)
	mux.HandleFunc("POST /setup", s.postSetup)
	mux.HandleFunc("GET /login", s.requireSetup(s.getLogin))
	mux.HandleFunc("POST /login", s.requireSetup(s.postLogin))
	mux.HandleFunc("POST /logout", s.requireCSRF(s.postLogout))
	s.pageRoutes(mux)
}

func (s *Server) getSetup(w http.ResponseWriter, r *http.Request) {
	if s.hasAdmin() {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.renderBare(w, "setup.html", map[string]any{"Title": "Set up KyDNS"})
}

// postSetup consumes the one-time token and creates the admin account. It is
// unauthenticated by necessity, so the token is the whole gate.
func (s *Server) postSetup(w http.ResponseWriter, r *http.Request) {
	if s.hasAdmin() {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "malformed form", http.StatusBadRequest)
		return
	}
	fail := func(msg string) {
		w.WriteHeader(http.StatusBadRequest)
		s.renderBare(w, "setup.html", map[string]any{"Title": "Set up KyDNS", "Error": msg})
	}

	// Constant-time so the token cannot be recovered by timing.
	given := r.PostFormValue("token")
	if subtle.ConstantTimeCompare([]byte(given), []byte(s.o.SetupToken)) != 1 {
		s.o.Logger.Warn("setup attempted with an invalid token", "source", sourceKey(r))
		fail("That setup token is not correct. It was printed to the server log at startup.")
		return
	}
	password := r.PostFormValue("password")
	if len(password) < minPasswordLen {
		fail("Choose a password of at least 12 characters.")
		return
	}
	if password != r.PostFormValue("confirm") {
		fail("The two passwords do not match.")
		return
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		fail(err.Error())
		return
	}
	if err := s.o.Store.SetAdminPassword(hash); err != nil {
		fail(err.Error())
		return
	}
	s.o.Logger.Info("admin account created")
	s.setSessionCookie(w, r, s.o.Sessions.Create())
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) getLogin(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.session(r); ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.renderBare(w, "login.html", map[string]any{"Title": "Sign in"})
}

func (s *Server) postLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "malformed form", http.StatusBadRequest)
		return
	}
	key := sourceKey(r)
	// Sleep before answering, so guessing gets slower without ever locking out.
	if d := s.o.Backoff.Delay(key); d > 0 {
		time.Sleep(d)
	}
	hash, err := s.o.Store.AdminHash()
	if err != nil || !auth.VerifyPassword(hash, r.PostFormValue("password")) {
		s.o.Backoff.Fail(key)
		s.o.Logger.Warn("failed login", "source", key)
		w.WriteHeader(http.StatusUnauthorized)
		s.renderBare(w, "login.html", map[string]any{
			"Title": "Sign in", "Error": "That password is not correct.",
		})
		return
	}
	s.o.Backoff.Reset(key)
	s.setSessionCookie(w, r, s.o.Sessions.Create())
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) postLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(auth.CookieName); err == nil {
		s.o.Sessions.Destroy(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: auth.CookieName, Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
