package settings

import (
	"errors"
	"strings"
	"testing"

	"github.com/yoshiofthewire/kydns-server/internal/store"
)

// valid is a settings value every test starts from, so each case changes
// exactly one thing and the failure names itself.
func valid() store.Settings {
	return store.Settings{
		PrivateDomain:     "home.arpa",
		ReverseZones:      []string{"192.168.1.0/24"},
		Upstreams:         []string{"tls://1.1.1.1:853"},
		AllowQuery:        []string{"192.168.0.0/16"},
		TTL:               60,
		CacheMinTTL:       5,
		CacheMaxTTL:       3600,
		NegativeMaxTTL:    300,
		CacheEntries:      10000,
		DiscoveryInterval: 30,
		HealthInterval:    30,
		HealthTimeout:     5,
		HealthWorkers:     8,
	}
}

func TestValidateAcceptsDefaults(t *testing.T) {
	if err := Validate(valid(), ""); err != nil {
		t.Fatalf("the shipped defaults must validate: %v", err)
	}
}

func TestValidateRejects(t *testing.T) {
	cases := []struct {
		name  string
		mut   func(*store.Settings)
		field string
	}{
		{"empty private domain", func(s *store.Settings) { s.PrivateDomain = "" }, "private_domain"},
		{"private domain is not a name", func(s *store.Settings) { s.PrivateDomain = "not a domain" }, "private_domain"},
		{"unparseable reverse zone", func(s *store.Settings) { s.ReverseZones = []string{"192.168.1.0"} }, "reverse_zones"},
		{"no upstreams", func(s *store.Settings) { s.Upstreams = nil }, "upstreams"},
		{"unparseable upstream", func(s *store.Settings) { s.Upstreams = []string{"tls://example.com"} }, "upstreams"},
		{"unparseable allow_query", func(s *store.Settings) { s.AllowQuery = []string{"192.168.0.1"} }, "allow_query"},
		// Default-closed: an empty allow list refuses every query, which is a
		// server that silently stops working.
		{"empty allow_query", func(s *store.Settings) { s.AllowQuery = nil }, "allow_query"},
		{"zero ttl", func(s *store.Settings) { s.TTL = 0 }, "ttl"},
		{"min ttl above max", func(s *store.Settings) { s.CacheMinTTL = 4000 }, "cache_min_ttl"},
		{"zero cache entries", func(s *store.Settings) { s.CacheEntries = 0 }, "cache_entries"},
		{"zero negative max ttl", func(s *store.Settings) { s.NegativeMaxTTL = 0 }, "negative_max_ttl"},
		{"zero discovery interval", func(s *store.Settings) { s.DiscoveryInterval = 0 }, "discovery.interval"},
		{"no health workers", func(s *store.Settings) { s.HealthWorkers = 0 }, "health.workers"},
		// A probe that outlives its own cycle stacks up forever.
		{"health timeout not below interval", func(s *store.Settings) { s.HealthTimeout = 30 }, "health.timeout"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := valid()
			tc.mut(&v)
			err := Validate(v, "")
			if err == nil {
				t.Fatal("accepted a value it must reject")
			}
			var fe FieldError
			if !errors.As(err, &fe) {
				t.Fatalf("error is not a FieldError, so no input can be highlighted: %v", err)
			}
			if fe.Field != tc.field {
				t.Errorf("blamed %q, want %q", fe.Field, tc.field)
			}
		})
	}
}

// A relative lease path would resolve against whatever directory the process
// happened to start in, which differs between the host and the container.
func TestValidateRejectsRelativeLeasePath(t *testing.T) {
	v := valid()
	v.DHCPLeaseFile = "leases"
	err := Validate(v, "")
	if err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("relative lease path accepted: %v", err)
	}
}

// An empty lease path is how discovery stays off, and must remain valid.
func TestValidateAllowsDiscoveryOff(t *testing.T) {
	v := valid()
	v.DHCPLeaseFile = ""
	if err := Validate(v, ""); err != nil {
		t.Fatalf("discovery off must validate: %v", err)
	}
}
