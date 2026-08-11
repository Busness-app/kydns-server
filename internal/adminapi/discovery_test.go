package adminapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/yoshiofthewire/kydns-server/internal/discovery/dhcp"
	"github.com/yoshiofthewire/kydns-server/internal/health"
	"github.com/yoshiofthewire/kydns-server/internal/registry"
	"github.com/yoshiofthewire/kydns-server/internal/store"
)

func newAPIWithProviders(t *testing.T) (http.Handler, string) {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "kydns.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	reg := registry.New(s, "home.arpa.", func() error { return nil })
	tok, err := reg.CreateToken("test")
	if err != nil {
		t.Fatal(err)
	}
	api := NewAPI(reg, nil, nil).WithProviders(
		func() []dhcp.Lease {
			return []dhcp.Lease{{
				Hostname: "laptop", IP: "192.168.1.50",
				MAC: "aa:bb:cc:dd:ee:01", Expires: time.Unix(4102444800, 0),
			}}
		},
		func() []health.Status {
			return []health.Status{{ServiceID: 1, Name: "kypost", State: "up", Since: time.Now()}}
		},
	)
	return api.Handler(), tok
}

func TestLeasesEndpoint(t *testing.T) {
	h, tok := newAPIWithProviders(t)
	rec := do(t, h, "GET", "/api/v1/leases", tok, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("= %d: %s", rec.Code, rec.Body)
	}
	var out struct {
		Leases []struct {
			Hostname string `json:"hostname"`
			Address  string `json:"address"`
		} `json:"leases"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Leases) != 1 || out.Leases[0].Hostname != "laptop" {
		t.Errorf("leases = %s", rec.Body)
	}
}

// With no provider attached the endpoint returns an empty list, not a 500.
func TestLeasesEndpointWithoutProvider(t *testing.T) {
	h, tok := newAPI(t)
	rec := do(t, h, "GET", "/api/v1/leases", tok, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("= %d: %s", rec.Code, rec.Body)
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte(`"leases":[]`)) {
		t.Errorf("body = %s, want an empty list", rec.Body)
	}
}

func TestPromoteEndpoint(t *testing.T) {
	h, tok := newAPIWithProviders(t)
	if rec := do(t, h, "POST", "/api/v1/leases/192.168.1.50/promote", tok, ""); rec.Code != http.StatusCreated {
		t.Fatalf("promote = %d: %s", rec.Code, rec.Body)
	}
	rec := do(t, h, "GET", "/api/v1/services", tok, "")
	if !bytes.Contains(rec.Body.Bytes(), []byte("laptop")) {
		t.Errorf("promoted service missing: %s", rec.Body)
	}
}

func TestPromoteUnknownIPIs404(t *testing.T) {
	h, tok := newAPIWithProviders(t)
	if rec := do(t, h, "POST", "/api/v1/leases/10.0.0.1/promote", tok, ""); rec.Code != http.StatusNotFound {
		t.Errorf("= %d, want 404", rec.Code)
	}
}

func TestPromoteWithoutDiscoveryIs404(t *testing.T) {
	h, tok := newAPI(t)
	if rec := do(t, h, "POST", "/api/v1/leases/192.168.1.50/promote", tok, ""); rec.Code != http.StatusNotFound {
		t.Errorf("= %d, want 404 when discovery is off", rec.Code)
	}
}

// Promoting twice conflicts: the name already exists as a service.
func TestPromoteTwiceConflicts(t *testing.T) {
	h, tok := newAPIWithProviders(t)
	do(t, h, "POST", "/api/v1/leases/192.168.1.50/promote", tok, "")
	if rec := do(t, h, "POST", "/api/v1/leases/192.168.1.50/promote", tok, ""); rec.Code != http.StatusConflict {
		t.Errorf("second promote = %d, want 409", rec.Code)
	}
}

func TestHealthEndpoint(t *testing.T) {
	h, tok := newAPIWithProviders(t)
	rec := do(t, h, "GET", "/api/v1/health", tok, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("= %d: %s", rec.Code, rec.Body)
	}
	var out struct {
		Health []struct {
			ServiceID int64  `json:"service_id"`
			State     string `json:"state"`
		} `json:"health"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Health) != 1 || out.Health[0].State != "up" {
		t.Errorf("health = %s", rec.Body)
	}
}

func TestHealthEndpointRequiresAuth(t *testing.T) {
	h, _ := newAPIWithProviders(t)
	for _, path := range []string{"/api/v1/leases", "/api/v1/health"} {
		if rec := do(t, h, "GET", path, "", ""); rec.Code != http.StatusUnauthorized {
			t.Errorf("GET %s without a token = %d, want 401", path, rec.Code)
		}
	}
}
