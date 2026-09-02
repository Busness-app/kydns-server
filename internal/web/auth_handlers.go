package web

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"time"

	"github.com/Busness-app/kydns-server/internal/auth"
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
	mux.HandleFunc("POST "+PathSetup, s.postSetup)
	mux.HandleFunc("GET /login", s.requireSetup(s.getLogin))
	mux.HandleFunc("POST "+PathLogin, s.requireSetup(s.postLogin))
	mux.HandleFunc("POST "+PathLogout, s.requireCSRF(s.postLogout))
	mux.HandleFunc("GET /auth/sso/login", s.getSSOLogin)
	mux.HandleFunc("GET /auth/sso/callback", s.getSSOCallback)
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
	sso, _ := s.o.Store.SSOSettings()
	ident, _ := s.o.Store.AdminIdentity()
	ssoEnabled := sso.Enabled || (ident != nil && ident.SSOSub != "")
	errMsg := r.URL.Query().Get("error")
	s.renderBare(w, "login.html", map[string]any{
		"Title":      "Sign in",
		"SSOEnabled": ssoEnabled,
		"Error":      errMsg,
	})
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
		sso, _ := s.o.Store.SSOSettings()
		ident, _ := s.o.Store.AdminIdentity()
		ssoEnabled := sso.Enabled || (ident != nil && ident.SSOSub != "")
		s.renderBare(w, "login.html", map[string]any{
			"Title":      "Sign in",
			"SSOEnabled": ssoEnabled,
			"Error":      "That password is not correct.",
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
	http.SetCookie(w, &http.Cookie{
		Name:     auth.CookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

const (
	cookieSSOState    = "kydns_sso_state"
	cookieSSOVerifier = "kydns_sso_verifier"
	cookieSSONonce    = "kydns_sso_nonce"
	cookieSSOLink     = "kydns_sso_link"
)

func (s *Server) getSSOLogin(w http.ResponseWriter, r *http.Request) {
	sso, err := s.o.Store.SSOSettings()
	ident, _ := s.o.Store.AdminIdentity()
	ssoActive := sso.Enabled || (ident != nil && ident.SSOSub != "") || r.URL.Query().Get("link") == "true"
	if err != nil || !ssoActive {
		http.Redirect(w, r, "/login?error=SSO+is+not+enabled", http.StatusSeeOther)
		return
	}

	verifier, challenge, err := auth.GeneratePKCE()
	if err != nil {
		http.Error(w, "failed to generate PKCE challenge", http.StatusInternalServerError)
		return
	}

	state, err := auth.GenerateState()
	if err != nil {
		http.Error(w, "failed to generate state", http.StatusInternalServerError)
		return
	}
	nonce, err := auth.GenerateState()
	if err != nil {
		http.Error(w, "failed to generate nonce", http.StatusInternalServerError)
		return
	}

	isLink := r.URL.Query().Get("link") == "true"
	s.setSSOCookie(w, r, cookieSSOState, state, 300)
	s.setSSOCookie(w, r, cookieSSOVerifier, verifier, 300)
	s.setSSOCookie(w, r, cookieSSONonce, nonce, 300)
	if isLink {
		s.setSSOCookie(w, r, cookieSSOLink, "1", 300)
	} else {
		s.clearSSOCookie(w, r, cookieSSOLink)
	}

	client := auth.NewSSOClient(sso.IssuerURL, sso.ClientID, sso.ClientSecret)
	redirectURI := s.ssoRedirectURI(r)
	authURL := client.AuthURL(redirectURI, state, nonce, challenge)
	http.Redirect(w, r, authURL, http.StatusSeeOther)
}

func (s *Server) getSSOCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	stateCookie, err := r.Cookie(cookieSSOState)
	if err != nil || stateCookie.Value == "" || stateCookie.Value != state {
		s.o.Logger.Warn("sso state mismatch or missing", "source", sourceKey(r))
		s.clearSSOCookies(w, r)
		w.WriteHeader(http.StatusBadRequest)
		sso, _ := s.o.Store.SSOSettings()
		s.renderBare(w, "login.html", map[string]any{
			"Title":      "Sign in",
			"SSOEnabled": sso.Enabled,
			"Error":      "Authentication state expired or invalid. Please try again.",
		})
		return
	}

	verifierCookie, err := r.Cookie(cookieSSOVerifier)
	if err != nil || verifierCookie.Value == "" {
		s.clearSSOCookies(w, r)
		w.WriteHeader(http.StatusBadRequest)
		sso, _ := s.o.Store.SSOSettings()
		s.renderBare(w, "login.html", map[string]any{
			"Title":      "Sign in",
			"SSOEnabled": sso.Enabled,
			"Error":      "Authentication session expired. Please try again.",
		})
		return
	}
	verifier := verifierCookie.Value
	nonceCookie, err := r.Cookie(cookieSSONonce)
	if err != nil || nonceCookie.Value == "" {
		s.clearSSOCookies(w, r)
		w.WriteHeader(http.StatusBadRequest)
		sso, _ := s.o.Store.SSOSettings()
		s.renderBare(w, "login.html", map[string]any{
			"Title": "Sign in", "SSOEnabled": sso.Enabled,
			"Error": "Authentication session expired. Please try again.",
		})
		return
	}
	nonce := nonceCookie.Value

	var isLink bool
	if linkCookie, err := r.Cookie(cookieSSOLink); err == nil && linkCookie.Value == "1" {
		isLink = true
	}
	s.clearSSOCookies(w, r)

	sso, err := s.o.Store.SSOSettings()
	if err != nil {
		http.Error(w, "failed to load SSO settings", http.StatusInternalServerError)
		return
	}

	client := auth.NewSSOClient(sso.IssuerURL, sso.ClientID, sso.ClientSecret)
	redirectURI := s.ssoRedirectURI(r)

	claims, err := client.ExchangeCode(r.Context(), redirectURI, code, verifier, nonce)
	if err != nil {
		s.o.Logger.Warn("sso code exchange failed", "error", err, "source", sourceKey(r))
		w.WriteHeader(http.StatusUnauthorized)
		s.renderBare(w, "login.html", map[string]any{
			"Title":      "Sign in",
			"SSOEnabled": sso.Enabled,
			"Error":      "Single Sign-On failed: " + err.Error(),
		})
		return
	}

	ident, err := s.o.Store.AdminIdentity()
	if err != nil {
		s.o.Logger.Error("failed to load admin identity", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	isAlreadyLinked := (ident != nil && ident.SSOSub != "" && ident.SSOSub == claims.Sub)

	// 1. Role enforcement: Must be Admin in IdP (or already linked to this local Admin)
	if !isLink && !isAlreadyLinked && !claims.IsAdmin() {
		s.o.Logger.Warn("sso non-admin rejected", "sub", claims.Sub, "role", claims.Role, "groups", claims.Groups, "username", claims.Username)
		w.WriteHeader(http.StatusForbidden)
		s.renderBare(w, "login.html", map[string]any{
			"Title":      "Sign in",
			"SSOEnabled": true,
			"Error":      "Access denied: KyDNS requires an Administrator account or a linked identity.",
		})
		return
	}

	// 2. Linking flow (initiated from Settings)
	if isLink {
		if _, ok := s.session(r); !ok {
			http.Redirect(w, r, "/login?error=Session+expired+during+linking", http.StatusSeeOther)
			return
		}
		if err := s.o.Store.LinkAdminSSO(claims.Sub, claims.Username, claims.Email); err != nil {
			s.o.Logger.Error("failed to link sso identity", "error", err)
			http.Redirect(w, r, "/settings?error=Failed+to+link+identity", http.StatusSeeOther)
			return
		}
		sso.Enabled = true
		_ = s.o.Store.SetSSOSettings(sso)
		s.o.Logger.Info("sso identity linked to admin", "sub", claims.Sub, "username", claims.Username)
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}

	// 3. Login flow
	if ident.SSOSub != "" {
		if ident.SSOSub != claims.Sub {
			s.o.Logger.Warn("sso subject mismatch", "expected", ident.SSOSub, "got", claims.Sub, "username", claims.Username)
			w.WriteHeader(http.StatusUnauthorized)
			s.renderBare(w, "login.html", map[string]any{
				"Title":      "Sign in",
				"SSOEnabled": true,
				"Error":      "This KySignOn account (" + claims.Username + ") is not linked to the KyDNS Admin. Log in with your password to manage SSO settings.",
			})
			return
		}
	} else {
		// First-time SSO login: Auto-link since KySignOn verified admin role
		_ = s.o.Store.LinkAdminSSO(claims.Sub, claims.Username, claims.Email)
		sso.Enabled = true
		_ = s.o.Store.SetSSOSettings(sso)
		s.o.Logger.Info("sso first-time auto-linked admin", "sub", claims.Sub, "username", claims.Username)
	}

	s.o.Logger.Info("sso login successful", "sub", claims.Sub, "username", claims.Username)
	s.setSessionCookie(w, r, s.o.Sessions.Create())
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) ssoRedirectURI(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	host := r.Host
	if fHost := r.Header.Get("X-Forwarded-Host"); fHost != "" {
		host = fHost
	}
	return fmt.Sprintf("%s://%s/auth/sso/callback", scheme, host)
}

func (s *Server) setSSOCookie(w http.ResponseWriter, r *http.Request, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/auth/sso/",
		MaxAge:   maxAge,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
	})
}

func (s *Server) clearSSOCookie(w http.ResponseWriter, r *http.Request, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/auth/sso/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
	})
}

func (s *Server) clearSSOCookies(w http.ResponseWriter, r *http.Request) {
	s.clearSSOCookie(w, r, cookieSSOState)
	s.clearSSOCookie(w, r, cookieSSOVerifier)
	s.clearSSOCookie(w, r, cookieSSONonce)
	s.clearSSOCookie(w, r, cookieSSOLink)
}
