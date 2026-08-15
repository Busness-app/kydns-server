package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
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
func (c *SSOClient) AuthURL(redirectURI, state, codeChallenge string) string {
	endpoints := c.DiscoverEndpoints(context.Background())

	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", c.ClientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", "openid profile email groups")
	q.Set("state", state)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")

	sep := "?"
	if strings.Contains(endpoints.AuthorizationEndpoint, "?") {
		sep = "&"
	}

	return fmt.Sprintf("%s%s%s", endpoints.AuthorizationEndpoint, sep, q.Encode())
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// ExchangeCode exchanges an authorization code with code_verifier for identity claims.
func (c *SSOClient) ExchangeCode(ctx context.Context, redirectURI, code, codeVerifier string) (*SSOTokenClaims, error) {
	endpoints := c.DiscoverEndpoints(ctx)

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", c.ClientID)
	if c.ClientSecret != "" {
		form.Set("client_secret", c.ClientSecret)
	}
	form.Set("code_verifier", codeVerifier)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoints.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token exchange failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errObj map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&errObj)
		return nil, fmt.Errorf("token endpoint returned status %d: %v", resp.StatusCode, errObj)
	}

	var tokResp tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokResp); err != nil {
		return nil, fmt.Errorf("decode token response: %w", err)
	}

	rawClaims := make(map[string]any)

	// Parse ID Token claims (JWT: header.payload.signature)
	if tokResp.IDToken != "" {
		parts := strings.Split(tokResp.IDToken, ".")
		if len(parts) == 3 {
			if payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1]); err == nil {
				_ = json.Unmarshal(payloadBytes, &rawClaims)
			}
		}
	}

	// Always query userinfo endpoint to enrich groups, roles, and profile info
	if endpoints.UserinfoEndpoint != "" && tokResp.AccessToken != "" {
		uReq, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoints.UserinfoEndpoint, nil)
		if err == nil {
			uReq.Header.Set("Authorization", "Bearer "+tokResp.AccessToken)
			uReq.Header.Set("Accept", "application/json")
			uResp, err := c.HTTPClient.Do(uReq)
			if err == nil && uResp.StatusCode == http.StatusOK {
				defer uResp.Body.Close()
				var uClaims map[string]any
				if err := json.NewDecoder(uResp.Body).Decode(&uClaims); err == nil {
					for k, v := range uClaims {
						rawClaims[k] = v
					}
				}
			}
		}
	}

	claims := parseClaimsMap(rawClaims)
	return claims, nil
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
