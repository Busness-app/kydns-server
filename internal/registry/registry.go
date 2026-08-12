package registry

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"

	"github.com/yoshiofthewire/kydns-server/internal/store"
)

// Registry is the application service both transports call. Validation lives
// here so the JSON API and the CLI cannot drift apart.
type Registry struct {
	s        *store.Store
	zone     string
	onChange func() error
}

func New(s *store.Store, zoneFQDN string, onChange func() error) *Registry {
	if onChange == nil {
		onChange = func() error { return nil }
	}
	return &Registry{s: s, zone: Normalize(zoneFQDN), onChange: onChange}
}

// Store exposes the underlying store for transactional import. Callers outside
// registry must not issue SQL through it.
func (r *Registry) Store() *store.Store { return r.s }

// Rebuild exposes the change hook so import can batch many writes into one
// snapshot rebuild.
func (r *Registry) Rebuild() error { return r.onChange() }

func (r *Registry) knownViews() (map[string]bool, error) {
	views, err := r.s.Views()
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, v := range views {
		out[v.Name] = true
	}
	return out, nil
}

// PutService validates, writes, then rebuilds. A failed validation never
// reaches the store and never triggers a rebuild.
func (r *Registry) PutService(svc store.Service) (int64, error) {
	svc.Name = strings.ToLower(strings.TrimSpace(svc.Name))
	if err := ValidateName(svc.Name+"."+r.zone, r.zone); err != nil {
		return 0, err
	}
	if len(svc.Addresses) == 0 {
		return 0, invalid("addresses", "addresses_required", "a service needs at least one address")
	}
	known, err := r.knownViews()
	if err != nil {
		return 0, err
	}
	for i, a := range svc.Addresses {
		if err := ValidateAddress(a.Address); err != nil {
			return 0, err
		}
		if a.View != "" && !known[a.View] {
			return 0, invalid(fmt.Sprintf("addresses[%d].view", i), "view_unknown", "view %q does not exist", a.View)
		}
	}
	svc.ProxyAddress = strings.TrimSpace(svc.ProxyAddress)
	if svc.ProxyAddress != "" {
		if err := ValidateAddress(svc.ProxyAddress); err != nil {
			return 0, invalid("proxy_address", "proxy_address_invalid", "%s", err)
		}
	}
	if svc.RouteViaProxy && svc.ProxyAddress == "" {
		return 0, invalid("proxy_address", "proxy_address_required",
			"routing through a proxy needs a proxy address")
	}
	for i, al := range svc.Aliases {
		svc.Aliases[i] = strings.ToLower(strings.TrimSpace(al))
		if err := ValidateName(svc.Aliases[i]+"."+r.zone, r.zone); err != nil {
			return 0, err
		}
	}
	id, err := r.s.PutService(svc)
	if err != nil {
		return 0, err
	}
	return id, r.onChange()
}

func (r *Registry) Services() ([]store.Service, error) { return r.s.Services() }

func (r *Registry) Service(id int64) (store.Service, error) { return r.s.Service(id) }

func (r *Registry) DeleteService(id int64) error {
	if err := r.s.DeleteService(id); err != nil {
		return err
	}
	return r.onChange()
}

func (r *Registry) PutRecord(rec store.Record) (int64, error) {
	rec.Name = Normalize(rec.Name)
	rec.Type = strings.ToUpper(strings.TrimSpace(rec.Type))
	if err := ValidateRecordType(rec.Type); err != nil {
		return 0, err
	}
	switch rec.Type {
	case "A", "AAAA":
		if err := ValidateName(rec.Name, r.zone); err != nil {
			return 0, err
		}
		if err := ValidateAddress(rec.Value); err != nil {
			return 0, err
		}
	case "CNAME":
		if err := ValidateName(rec.Name, r.zone); err != nil {
			return 0, err
		}
		rec.Value = Normalize(rec.Value)
	case "PTR":
		// Checking for ".arpa." alone would wrongly accept names in the
		// default private domain, since home.arpa is itself under .arpa.
		if !strings.HasSuffix(rec.Name, ".in-addr.arpa.") && !strings.HasSuffix(rec.Name, ".ip6.arpa.") {
			return 0, invalid("name", "ptr_not_arpa",
				"a PTR name must be under in-addr.arpa. or ip6.arpa.")
		}
		rec.Value = Normalize(rec.Value)
	}
	known, err := r.knownViews()
	if err != nil {
		return 0, err
	}
	if rec.View != "" && !known[rec.View] {
		return 0, invalid("view", "view_unknown", "view %q does not exist", rec.View)
	}
	id, err := r.s.PutRecord(rec)
	if err != nil {
		return 0, err
	}
	return id, r.onChange()
}

func (r *Registry) Records() ([]store.Record, error) { return r.s.Records() }

func (r *Registry) DeleteRecord(id int64) error {
	if err := r.s.DeleteRecord(id); err != nil {
		return err
	}
	return r.onChange()
}

func (r *Registry) PutView(v store.View) error {
	v.Name = strings.ToLower(strings.TrimSpace(v.Name))
	if err := ValidateLabel(v.Name); err != nil {
		return invalid("name", "view_name_invalid", "view name %q must be a single DNS label", v.Name)
	}
	if len(v.Subnets) == 0 {
		return invalid("subnets", "subnets_required", "a view needs at least one subnet")
	}
	for i, c := range v.Subnets {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return invalid(fmt.Sprintf("subnets[%d]", i), "cidr_invalid", "%q is not a CIDR", c)
		}
		v.Subnets[i] = p.Masked().String()
	}
	if err := r.s.PutView(v); err != nil {
		return err
	}
	return r.onChange()
}

func (r *Registry) Views() ([]store.View, error) { return r.s.Views() }

func (r *Registry) DeleteView(name string) error {
	if err := r.s.DeleteView(name); err != nil {
		return err
	}
	return r.onChange()
}

const tokenPrefix = "kydns_"

// GenerateToken returns a new plaintext token and its hash. Tokens are
// high-entropy randoms, so SHA-256 is right: a slow KDF on every API call
// would cost real latency and buy nothing against a 256-bit search space.
func GenerateToken() (string, string) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	plaintext := tokenPrefix + hex.EncodeToString(buf)
	return plaintext, HashToken(plaintext)
}

func HashToken(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}

func (r *Registry) CreateToken(label string) (string, error) {
	plaintext, hash := GenerateToken()
	if _, err := r.s.PutToken(store.Token{Label: label, Hash: hash}); err != nil {
		return "", err
	}
	return plaintext, nil
}

// AuthenticateToken compares in constant time against every stored hash.
func (r *Registry) AuthenticateToken(plaintext string) bool {
	if !strings.HasPrefix(plaintext, tokenPrefix) {
		return false
	}
	want := HashToken(plaintext)
	toks, err := r.s.Tokens()
	if err != nil {
		return false
	}
	ok := false
	for _, t := range toks {
		if subtle.ConstantTimeCompare([]byte(t.Hash), []byte(want)) == 1 {
			ok = true
			_ = r.s.TouchToken(t.ID)
		}
	}
	return ok
}

func (r *Registry) Tokens() ([]store.Token, error) { return r.s.Tokens() }

func (r *Registry) DeleteToken(id int64) error { return r.s.DeleteToken(id) }
