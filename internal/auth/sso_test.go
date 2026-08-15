package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGeneratePKCEAndState(t *testing.T) {
	verifier, challenge, err := GeneratePKCE()
	if err != nil {
		t.Fatalf("GeneratePKCE() error = %v", err)
	}
	if len(verifier) < 40 {
		t.Errorf("verifier too short: %q", verifier)
	}
	if len(challenge) < 40 {
		t.Errorf("challenge too short: %q", challenge)
	}

	state, err := GenerateState()
	if err != nil {
		t.Fatalf("GenerateState() error = %v", err)
	}
	if len(state) != 32 {
		t.Errorf("state length = %d, want 32", len(state))
	}
}

func TestSSOAuthURLAndExchangeCode(t *testing.T) {
	// Mock KySignOn Server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			_ = r.ParseForm()
			if r.FormValue("code") != "valid-test-code" {
				http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
				return
			}

			// Construct sample JWT ID token
			claims := map[string]any{
				"sub":      "user-uuid-12345",
				"username": "admin_yoshi",
				"email":    "admin@urlxl.com",
				"role":     "admin",
				"iss":      "https://auth.urlxl.com",
			}
			claimsJSON, _ := json.Marshal(claims)
			encodedClaims := base64.RawURLEncoding.EncodeToString(claimsJSON)
			fakeIDToken := "header." + encodedClaims + ".signature"

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "mock-access-token",
				"id_token":     fakeIDToken,
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer mockServer.Close()

	client := NewSSOClient(mockServer.URL, "kydns-client", "secret")
	authURL := client.AuthURL("http://localhost:8053/auth/sso/callback", "state123", "challenge123")
	if !strings.Contains(authURL, "/oauth/authorize") || !strings.Contains(authURL, "client_id=kydns-client") {
		t.Errorf("unexpected AuthURL: %s", authURL)
	}

	claims, err := client.ExchangeCode(context.Background(), "http://localhost:8053/auth/sso/callback", "valid-test-code", "verifier123")
	if err != nil {
		t.Fatalf("ExchangeCode failed: %v", err)
	}
	if claims.Sub != "user-uuid-12345" || claims.Username != "admin_yoshi" || claims.Role != "admin" {
		t.Errorf("unexpected claims: %+v", claims)
	}
}
