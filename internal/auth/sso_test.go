package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func testOIDCServer(t *testing.T, clientID, nonce string, claims map[string]any, tamper ...bool) *httptest.Server {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer": srv.URL, "authorization_endpoint": srv.URL + "/oauth/authorize",
				"token_endpoint": srv.URL + "/oauth/token", "userinfo_endpoint": srv.URL + "/oauth/userinfo",
				"jwks_uri": srv.URL + "/oauth/jwks", "id_token_signing_alg_values_supported": []string{"RS256"},
			})
		case "/oauth/jwks":
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
				Key: &key.PublicKey, KeyID: "test", Algorithm: string(jose.RS256), Use: "sig",
			}}})
		case "/oauth/token":
			signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key},
				(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test"))
			base := map[string]any{"iss": srv.URL, "aud": clientID, "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "nonce": nonce}
			for k, v := range claims {
				base[k] = v
			}
			raw, _ := jwt.Signed(signer).Claims(base).Serialize()
			if len(tamper) != 0 && tamper[0] {
				parts := strings.Split(raw, ".")
				parts[2] = "x" + parts[2][1:]
				raw = strings.Join(parts, ".")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "mock-access-token", "id_token": raw, "token_type": "Bearer"})
		case "/oauth/userinfo":
			_ = json.NewEncoder(w).Encode(claims)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

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
	mockServer := testOIDCServer(t, "kydns-client", "nonce123", map[string]any{
		"sub": "user-uuid-12345", "username": "admin_yoshi", "email": "admin@urlxl.com", "role": "admin",
	})

	client := NewSSOClient(mockServer.URL, "kydns-client", "secret")
	authURL := client.AuthURL("http://localhost:8053/auth/sso/callback", "state123", "nonce123", "challenge123")
	if !strings.Contains(authURL, "/oauth/authorize") || !strings.Contains(authURL, "client_id=kydns-client") {
		t.Errorf("unexpected AuthURL: %s", authURL)
	}

	claims, err := client.ExchangeCode(context.Background(), "http://localhost:8053/auth/sso/callback", "valid-test-code", "verifier123", "nonce123")
	if err != nil {
		t.Fatalf("ExchangeCode failed: %v", err)
	}
	if claims.Sub != "user-uuid-12345" || claims.Username != "admin_yoshi" || claims.Role != "admin" {
		t.Errorf("unexpected claims: %+v", claims)
	}
	if !claims.IsAdmin() {
		t.Errorf("expected claims.IsAdmin() == true")
	}
}

func TestExchangeCodeRejectsWrongNonce(t *testing.T) {
	mockServer := testOIDCServer(t, "kydns-client", "issued-nonce", map[string]any{"sub": "user-1"})
	client := NewSSOClient(mockServer.URL, "kydns-client", "")
	if _, err := client.ExchangeCode(context.Background(), "http://localhost/callback", "code", "verifier", "different-nonce"); err == nil || !strings.Contains(err.Error(), "nonce mismatch") {
		t.Fatalf("ExchangeCode error = %v, want nonce mismatch", err)
	}
}

func TestExchangeCodeRejectsInvalidSignature(t *testing.T) {
	mockServer := testOIDCServer(t, "kydns-client", "nonce", map[string]any{"sub": "user-1"}, true)
	client := NewSSOClient(mockServer.URL, "kydns-client", "")
	if _, err := client.ExchangeCode(context.Background(), "http://localhost/callback", "code", "verifier", "nonce"); err == nil || !strings.Contains(err.Error(), "verify ID token") {
		t.Fatalf("ExchangeCode error = %v, want signature verification failure", err)
	}
}

func TestAuthentikOIDCDiscoveryAndGroups(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"authorization_endpoint": "https://authentik.urlxl.com/application/o/authorize/",
				"token_endpoint":         "https://authentik.urlxl.com/application/o/token/",
				"userinfo_endpoint":      "https://authentik.urlxl.com/application/o/userinfo/",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer mockServer.Close()

	client := NewSSOClient(mockServer.URL, "authentik-client", "secret")
	endpoints := client.DiscoverEndpoints(context.Background())
	if endpoints.AuthorizationEndpoint != "https://authentik.urlxl.com/application/o/authorize/" {
		t.Errorf("unexpected discovered auth endpoint: %s", endpoints.AuthorizationEndpoint)
	}

	// Test Authentik group claims
	authentikClaims := map[string]any{
		"sub":                "authentik-sub-123",
		"preferred_username": "akadmin",
		"email":              "admin@urlxl.com",
		"groups":             []string{"authentik default admins", "kydns_admin"},
	}
	parsed := parseClaimsMap(authentikClaims)
	if !parsed.IsAdmin() {
		t.Errorf("expected Authentik admin groups to satisfy IsAdmin()")
	}
	if parsed.Username != "akadmin" {
		t.Errorf("expected username 'akadmin', got %q", parsed.Username)
	}

	// Test Keycloak realm_access claims
	keycloakClaims := map[string]any{
		"sub":      "kc-sub-456",
		"username": "kcadmin",
		"realm_access": map[string]any{
			"roles": []any{"admin", "offline_access"},
		},
	}
	kcParsed := parseClaimsMap(keycloakClaims)
	if !kcParsed.IsAdmin() {
		t.Errorf("expected Keycloak realm_access.roles to satisfy IsAdmin()")
	}
}
