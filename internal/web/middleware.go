// Package web is the HTML transport. Like adminapi it holds no business rules:
// both call the same registry service.
package web

import (
	"log/slog"
	"net"
	"net/http"
	"strings"

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
	Store      *store.Store
	Registry   *registry.Registry
	API        *adminapi.API
	Config     *config.Config
	Sessions   *auth.Sessions
	Backoff    *auth.Backoff
	ACL        *dnsserver.ACL
	Cache      *dnsserver.Cache
	Metrics    *dnsserver.Metrics
	SetupToken string
	Logger     *slog.Logger

	// Settings is the single write path for the settings the database owns. It
	// is nil when the service is not wired, which the screen renders as the
	// read-only table rather than as a broken form.
	Settings *settings.Service

	// RestartPending names the settings whose stored value differs from the one
	// the process is running. Empty is the normal case.
	RestartPending func() []RestartItem

	// Leases, Health and Upstreams are nil when the corresponding subsystem is
	// off, which the screens render as "not enabled" rather than as empty.
	Leases    func() []dhcp.Lease
	Health    func() []health.Status
	Upstreams func() []dnsserver.UpstreamStatus

	// Policy is nil when filtering is not wired, which the screen renders as
	// "not enabled" rather than as an empty tab.
	Policy *policy.Service

	// Replication reports what this node is, read per request so promotion
	// takes effect without a restart. Nil means nothing is replicating, which
	// is a standalone node and edits freely.
	Replication func() ReplicaStatus
}

// ReplicaStatus is the slice of app.ReplicaStatus this transport renders. web
// cannot import internal/app, because app already imports web to wire it.
type ReplicaStatus struct {
	Role         string
	PrimaryAddr  string
	LastSyncUnix int64
}

// roleReplica mirrors app.Role's replica value, for the same reason.
const roleReplica = "replica"

// The POST paths a replica must still answer, named so the exemption list and
// route registration cannot drift apart. The replication screen registers its
// promote button at PathPromote, so the one button that ends a replica's
// read-only life is never refused by this gate. Promotion goes through the web
// transport, not the API's own exempt path, because the screen calls adminapi
// in-process.
const (
	PathSetup   = "/setup"
	PathLogin   = "/login"
	PathLogout  = "/logout"
	PathPromote = "/replication/promote"
)

// webWriteExempt is the whole exemption list. Signing in is how an operator
// reaches the promote button, being unable to sign out of a replica would be
// its own trap, and a replica that refuses to be promoted is the outage this
// feature exists to end.
var webWriteExempt = map[string]bool{
	PathSetup: true, PathLogin: true, PathLogout: true, PathPromote: true,
}

// managedBy names the box to make the change on.
func (s ReplicaStatus) managedBy() string {
	if s.PrimaryAddr == "" {
		return "its primary"
	}
	return s.PrimaryAddr
}

// replica reports the current status when this node is a replica.
func (s *Server) replica() (ReplicaStatus, bool) {
	if s.o.Replication == nil {
		return ReplicaStatus{}, false
	}
	st := s.o.Replication()
	return st, st.Role == roleReplica
}

// WriteGate refuses form posts on a replica: the primary overwrites this
// node's config on the next pull, so an accepted edit is a silently discarded
// one. It wraps the handler rather than the routes, so a POST added later is
// refused without anyone remembering to gate it.
//
// The admin API keeps its own gate: a browser needs a page, not JSON.
func (s *Server) WriteGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead ||
			strings.HasPrefix(r.URL.Path, adminapi.PathPrefix) || webWriteExempt[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}
		st, isReplica := s.replica()
		if !isReplica {
			next.ServeHTTP(w, r)
			return
		}
		// An anonymous poster gets the login redirect it always got: this gate
		// sits outside the session check and must not tell a stranger where
		// the primary is.
		if _, ok := s.session(r); !ok {
			next.ServeHTTP(w, r)
			return
		}
		w.WriteHeader(http.StatusConflict)
		s.renderBare(w, "readonly.html", map[string]any{
			"Title": "Read-only replica", "ManagedBy": st.managedBy(),
		})
	})
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

// requireSessionJSON is requireSession for the polled endpoints the pages
// fetch. A redirect to an HTML login page is not an answer a fetch can use, so
// an expired session gets a status the caller can act on.
func (s *Server) requireSessionJSON(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := s.session(r); !ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"signed out"}`))
			return
		}
		next(w, r)
	}
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
