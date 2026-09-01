package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// SSOTokenClaims represents the verified claims from KySignOn, Authentik, Keycloak, or any OIDC provider.
type SSOTokenClaims struct {
	Sub               string         `json:"sub"`
	Username          string         `json:"username"`
	PreferredUsername string         `json:"preferred_username"`
	Email             string         `json:"email"`
	DisplayName       string         `json:"name"`
	Role              string         `json:"role"`
	Roles             []string       `json:"roles"`
	Groups            []string       `json:"groups"`
	Issuer            string         `json:"iss"`
	RawClaims         map[string]any `json:"-"`
}

// IsAdmin returns true if the claims indicate Administrator status in KySignOn, Authentik, or Keycloak.
func (c *SSOTokenClaims) IsAdmin() bool {
	if strings.EqualFold(c.Role, "admin") || strings.EqualFold(c.Role, "administrator") {
		return true
	}
	for _, g := range c.Groups {
		gClean := strings.ToLower(strings.TrimSpace(g))
		if gClean == "admin" || gClean == "admins" || gClean == "kydns_admin" || gClean == "kydns-admin" || gClean == "kydns_admins" || gClean == "authentik default admins" {
			return true
		}
	}
	for _, r := range c.Roles {
		rClean := strings.ToLower(strings.TrimSpace(r))
		if rClean == "admin" || rClean == "administrator" || rClean == "kydns_admin" {
			return true
		}
	}
	return false
}

type OIDCEndpoints struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// SSOClient manages OAuth 2.0 PKCE Authorization Code flow with any OIDC provider.
type SSOClient struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string
	HTTPClient   *http.Client
}

func NewSSOClient(issuerURL, clientID, clientSecret string) *SSOClient {
	return &SSOClient{
		IssuerURL:    strings.TrimRight(issuerURL, "/"),
		ClientID:     clientID,
		ClientSecret: clientSecret,
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// DiscoverEndpoints queries OIDC discovery configuration or falls back to standard endpoints.
func (c *SSOClient) DiscoverEndpoints(ctx context.Context) OIDCEndpoints {
	defaults := OIDCEndpoints{
		AuthorizationEndpoint: c.IssuerURL + "/oauth/authorize",
		TokenEndpoint:         c.IssuerURL + "/oauth/token",
		UserinfoEndpoint:      c.IssuerURL + "/oauth/userinfo",
	}

	wellKnown := c.IssuerURL + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnown, nil)
	if err != nil {
		return defaults
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return defaults
	}
	defer resp.Body.Close()

	var disc OIDCEndpoints
	if err := json.NewDecoder(resp.Body).Decode(&disc); err != nil {
		return defaults
	}

	if disc.AuthorizationEndpoint == "" {
		disc.AuthorizationEndpoint = defaults.AuthorizationEndpoint
	}
	if disc.TokenEndpoint == "" {
		disc.TokenEndpoint = defaults.TokenEndpoint
	}
	if disc.UserinfoEndpoint == "" {
		disc.UserinfoEndpoint = defaults.UserinfoEndpoint
	}

	return disc
}

// GeneratePKCE creates an RFC 7636 code verifier and S256 code challenge.
func GeneratePKCE() (verifier, challenge string, err error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(buf)
	h := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(h[:])
	return verifier, challenge, nil
}

// GenerateState creates a random state token to protect against CSRF during OAuth flow.
func GenerateState() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// AuthURL constructs the authorization URL using OIDC discovery or default paths.
func (c *SSOClient) AuthURL(redirectURI, state, nonce, codeChallenge string) string {
	endpoints := c.DiscoverEndpoints(context.Background())

	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", c.ClientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", "openid profile email groups")
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")

	sep := "?"
	if strings.Contains(endpoints.AuthorizationEndpoint, "?") {
		sep = "&"
	}

	return fmt.Sprintf("%s%s%s", endpoints.AuthorizationEndpoint, sep, q.Encode())
}

// ExchangeCode exchanges an authorization code with code_verifier for identity claims.
func (c *SSOClient) ExchangeCode(ctx context.Context, redirectURI, code, codeVerifier, nonce string) (*SSOTokenClaims, error) {
	ctx = oidc.ClientContext(ctx, c.HTTPClient)
	provider, err := oidc.NewProvider(ctx, c.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("discover OIDC provider: %w", err)
	}
	config := oauth2.Config{
		ClientID: c.ClientID, ClientSecret: c.ClientSecret, Endpoint: provider.Endpoint(),
		RedirectURL: redirectURI, Scopes: []string{oidc.ScopeOpenID, "profile", "email", "groups"},
	}
	token, err := config.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", codeVerifier))
	if err != nil {
		return nil, fmt.Errorf("token exchange failed: %w", err)
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, fmt.Errorf("token response has no ID token")
	}
	idToken, err := provider.Verifier(&oidc.Config{ClientID: c.ClientID}).Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("verify ID token: %w", err)
	}
	if nonce == "" || subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(nonce)) != 1 {
		return nil, fmt.Errorf("verify ID token: nonce mismatch")
	}
	rawClaims := make(map[string]any)
	if err := idToken.Claims(&rawClaims); err != nil {
		return nil, fmt.Errorf("decode verified ID token claims: %w", err)
	}
	if idToken.Subject == "" {
		return nil, fmt.Errorf("verify ID token: subject is empty")
	}
	if userInfo, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(token)); err == nil {
		if userInfo.Subject != idToken.Subject {
			return nil, fmt.Errorf("verify userinfo: subject mismatch")
		}
		var userClaims map[string]any
		if err := userInfo.Claims(&userClaims); err == nil {
			for k, v := range userClaims {
				rawClaims[k] = v
			}
		}
	}
	return parseClaimsMap(rawClaims), nil
}

func parseClaimsMap(m map[string]any) *SSOTokenClaims {
	c := &SSOTokenClaims{
		RawClaims: m,
	}

	if s, ok := m["sub"].(string); ok {
		c.Sub = s
	}
	if u, ok := m["username"].(string); ok {
		c.Username = u
	}
	if pu, ok := m["preferred_username"].(string); ok {
		c.PreferredUsername = pu
	}
	if e, ok := m["email"].(string); ok {
		c.Email = e
	}
	if n, ok := m["name"].(string); ok {
		c.DisplayName = n
	}
	if r, ok := m["role"].(string); ok {
		c.Role = r
	}
	if iss, ok := m["iss"].(string); ok {
		c.Issuer = iss
	}

	// Extract groups (strings or array)
	extractStrings := func(val any) []string {
		var out []string
		switch v := val.(type) {
		case []any:
			for _, item := range v {
				if str, ok := item.(string); ok {
					out = append(out, str)
				}
			}
		case []string:
			out = append(out, v...)
		case string:
			for _, item := range strings.Split(v, ",") {
				if str := strings.TrimSpace(item); str != "" {
					out = append(out, str)
				}
			}
		}
		return out
	}

	if gVal, ok := m["groups"]; ok {
		c.Groups = append(c.Groups, extractStrings(gVal)...)
	}
	if akVal, ok := m["ak_groups"]; ok {
		c.Groups = append(c.Groups, extractStrings(akVal)...)
	}
	if rVal, ok := m["roles"]; ok {
		c.Roles = append(c.Roles, extractStrings(rVal)...)
	}

	// Keycloak realm_access.roles
	if ra, ok := m["realm_access"].(map[string]any); ok {
		if rar, ok := ra["roles"]; ok {
			c.Roles = append(c.Roles, extractStrings(rar)...)
		}
	}

	if c.Username == "" && c.PreferredUsername != "" {
		c.Username = c.PreferredUsername
	}
	if c.Username == "" && c.Email != "" {
		c.Username = c.Email
	}

	return c
}
