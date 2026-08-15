package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// SSOTokenClaims represents the verified claims from KySignOn.
type SSOTokenClaims struct {
	Sub               string `json:"sub"`
	Username          string `json:"username"`
	PreferredUsername string `json:"preferred_username"`
	Email             string `json:"email"`
	DisplayName       string `json:"name"`
	Role              string `json:"role"`
	Issuer            string `json:"iss"`
}

// SSOClient manages OAuth 2.0 PKCE Authorization Code flow with KySignOn.
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

// AuthURL constructs the KySignOn authorization URL.
func (c *SSOClient) AuthURL(redirectURI, state, codeChallenge string) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", c.ClientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", "openid profile email")
	q.Set("state", state)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")

	return fmt.Sprintf("%s/oauth/authorize?%s", c.IssuerURL, q.Encode())
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// ExchangeCode exchanges an authorization code with code_verifier for identity claims.
func (c *SSOClient) ExchangeCode(ctx context.Context, redirectURI, code, codeVerifier string) (*SSOTokenClaims, error) {
	tokenEndpoint := c.IssuerURL + "/oauth/token"
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", c.ClientID)
	if c.ClientSecret != "" {
		form.Set("client_secret", c.ClientSecret)
	}
	form.Set("code_verifier", codeVerifier)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
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

	// Parse ID Token claims (JWT: header.payload.signature)
	parts := strings.Split(tokResp.IDToken, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid id_token format")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode id_token payload: %w", err)
	}

	var claims SSOTokenClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("parse id_token claims: %w", err)
	}

	// Also fetch /oauth/userinfo if username or role missing from ID token
	if claims.Username == "" || claims.Role == "" {
		userinfoEndpoint := c.IssuerURL + "/oauth/userinfo"
		uReq, err := http.NewRequestWithContext(ctx, http.MethodGet, userinfoEndpoint, nil)
		if err == nil {
			uReq.Header.Set("Authorization", "Bearer "+tokResp.AccessToken)
			uReq.Header.Set("Accept", "application/json")
			uResp, err := c.HTTPClient.Do(uReq)
			if err == nil && uResp.StatusCode == http.StatusOK {
				defer uResp.Body.Close()
				_ = json.NewDecoder(uResp.Body).Decode(&claims)
			}
		}
	}

	if claims.Username == "" && claims.PreferredUsername != "" {
		claims.Username = claims.PreferredUsername
	}

	return &claims, nil
}
