package store

import (
	"errors"
	"testing"
)

func TestAdminPasswordRoundTrip(t *testing.T) {
	s := open(t)
	has, err := s.HasAdmin()
	if err != nil {
		t.Fatal(err)
	}
	if has {
		t.Fatal("HasAdmin() = true on a fresh database")
	}
	if _, err := s.AdminHash(); !errors.Is(err, ErrNotFound) {
		t.Errorf("AdminHash() error = %v, want ErrNotFound before setup", err)
	}
	if err := s.SetAdminPassword("$argon2id$fake"); err != nil {
		t.Fatal(err)
	}
	if has, _ = s.HasAdmin(); !has {
		t.Error("HasAdmin() = false after SetAdminPassword()")
	}
	got, err := s.AdminHash()
	if err != nil {
		t.Fatal(err)
	}
	if got != "$argon2id$fake" {
		t.Errorf("AdminHash() = %q", got)
	}
	// Setting again replaces rather than inserting a second admin.
	if err := s.SetAdminPassword("$argon2id$second"); err != nil {
		t.Fatal(err)
	}
	if got, _ = s.AdminHash(); got != "$argon2id$second" {
		t.Errorf("AdminHash() = %q, want the replacement", got)
	}
}
