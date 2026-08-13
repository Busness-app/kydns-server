// Package web is the HTML transport. Like adminapi it holds no business rules:
// both call the same registry service.
package web

import (
	"log/slog"
	"net"
	"net/http"

	"github.com/yoshiofthewire/kydns-server/internal/adminapi"
	"github.com/yoshiofthewire/kydns-server/internal/auth"
	"github.com/yoshiofthewire/kydns-server/internal/config"
	"github.com/yoshiofthewire/kydns-server/internal/discovery/dhcp"
	"github.com/yoshiofthewire/kydns-server/internal/dnsserver"
	"github.com/yoshiofthewire/kydns-server/internal/health"
	"github.com/yoshiofthewire/kydns-server/internal/policy"
	"github.com/yoshiofthewire/kydns-server/internal/registry"
	"github.com/yoshiofthewire/kydns-server/internal/settings"
	"github.com/yoshiofthewire/kydns-server/internal/store"
)

type Options struct {
	Store          *store.Store
	Registry       *registry.Registry
	API            *adminapi.API
	Config         *config.Config
	Sessions       *auth.Sessions
	Backoff        *auth.Backoff
	ACL            *dnsserver.ACL
	Cache          *dnsserver.Cache
	AllowTailscale bool
	SetupToken     string
	Logger         *slog.Logger

	// Settings is the single write path for the settings the database owns.
	Settings *settings.Service

	// Leases, Health and Upstreams are nil when the corresponding subsystem is
	// off, which the screens render as "not enabled" rather than as empty.
	Leases    func() []dhcp.Lease
	Health    func() []health.Status
	Upstreams func() []dnsserver.UpstreamStatus

	// Policy is nil when filtering is not wired, which the screen renders as
	// "not enabled" rather than as an empty tab.
	Policy *policy.Service
}

type Server struct{ o Options }

func New(o Options) *Server {
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	return &Server{o: o}
}

// Options exposes the wiring for tests and for handlers in sibling files.
func (s *Server) Options() Options { return s.o }

const minPasswordLen = auth.MinPasswordLen

func (s *Server) hasAdmin() bool {
	ok, err := s.o.Store.HasAdmin()
	if err != nil {
		s.o.Logger.Error("check admin", "error", err)
		return false
	}
	return ok
}

// requireSetup funnels every route to /setup until an admin password exists.
func (s *Server) requireSetup(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.hasAdmin() {
			http.Redirect(w, r, "/setup", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

// requireSession redirects anonymous visitors to the login page.
func (s *Server) requireSession(next http.HandlerFunc) http.HandlerFunc {
	return s.requireSetup(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := s.session(r); !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r)
	})
}

// requireCSRF rejects a form post whose token does not belong to its session.
// SameSite=Lax already blocks most cross-site posts; this closes the rest.
func (s *Server) requireCSRF(next http.HandlerFunc) http.HandlerFunc {
	return s.requireSetup(func(w http.ResponseWriter, r *http.Request) {
		sess, ok := s.session(r)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "malformed form", http.StatusBadRequest)
			return
		}
		if !s.o.Sessions.ValidCSRF(sess.ID, r.PostFormValue("csrf_token")) {
			http.Error(w, "invalid CSRF token", http.StatusForbidden)
			return
		}
		next(w, r)
	})
}

func (s *Server) session(r *http.Request) (*auth.Session, bool) {
	c, err := r.Cookie(auth.CookieName)
	if err != nil {
		return nil, false
	}
	return s.o.Sessions.Get(c.Value)
}

func (s *Server) setSessionCookie(w http.ResponseWriter, r *http.Request, sess *auth.Session) {
	http.SetCookie(w, &http.Cookie{
		Name:     auth.CookieName,
		Value:    sess.ID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
	})
}

func sourceKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
