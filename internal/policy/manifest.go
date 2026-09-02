package policy

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/Busness-app/kydns-server/internal/store"
)

// builtinJSON is the versioned manifest of maintained sources. A release can
// change it without touching policy code.
//
//go:embed builtin.json
var builtinJSON []byte

// Builtin is one shipped source, with the license and attribution its terms
// require and the UI displays.
type Builtin struct {
	Name            string `json:"name"`
	Description     string `json:"description"`
	URL             string `json:"url"`
	Format          string `json:"format"`
	License         string `json:"license"`
	Attribution     string `json:"attribution"`
	IntervalSeconds int64  `json:"interval_seconds"`
}

type Manifest struct {
	Version int       `json:"version"`
	Lists   []Builtin `json:"lists"`
}

// BuiltinManifest parses the embedded manifest and rejects an entry that would
// not be a legal list, so a bad release fails at startup rather than at
// refresh time.
func BuiltinManifest() (Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(builtinJSON, &m); err != nil {
		return Manifest{}, fmt.Errorf("builtin manifest: %w", err)
	}
	if m.Version < 1 {
		return Manifest{}, errors.New("builtin manifest: version is required")
	}
	for _, l := range m.Lists {
		if l.Name == "" || l.License == "" || l.Attribution == "" {
			return Manifest{}, fmt.Errorf("builtin manifest: %q lacks name, license or attribution", l.Name)
		}
		if !ValidFormat(l.Format) {
			return Manifest{}, fmt.Errorf("builtin manifest: %q declares format %q", l.Name, l.Format)
		}
		if l.IntervalSeconds <= 0 {
			return Manifest{}, fmt.Errorf("builtin manifest: %q has no refresh interval", l.Name)
		}
	}
	return m, nil
}

// SeedBuiltins inserts any manifest entry the database does not already hold,
// by name. It never updates an existing row: a list the operator disabled or
// retuned stays that way across upgrades.
func SeedBuiltins(st *store.Store) error {
	m, err := BuiltinManifest()
	if err != nil {
		return err
	}
	have, err := st.BlacklistListMetas()
	if err != nil {
		return err
	}
	known := make(map[string]bool, len(have))
	for _, l := range have {
		known[l.Name] = true
	}
	for _, b := range m.Lists {
		if known[b.Name] {
			continue
		}
		if _, err := st.PutBlacklistList(store.BlacklistList{
			Name: b.Name, URL: b.URL, Format: b.Format,
			Description:     b.Description + " (" + b.License + ", " + b.Attribution + ")",
			Enabled:         true,
			Builtin:         true,
			IntervalSeconds: b.IntervalSeconds,
		}); err != nil {
			return err
		}
	}
	return nil
}
