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

	// Test AdminIdentity and SSO Linking
	ident, err := s.AdminIdentity()
	if err != nil {
		t.Fatalf("AdminIdentity() error = %v", err)
	}
	if ident.PasswordHash != "$argon2id$second" || ident.SSOSub != "" {
		t.Errorf("unexpected AdminIdentity: %+v", ident)
	}

	if err := s.LinkAdminSSO("sso-sub-123", "admin_yoshi", "admin@urlxl.com"); err != nil {
		t.Fatalf("LinkAdminSSO() error = %v", err)
	}

	ident, err = s.AdminIdentity()
	if err != nil {
		t.Fatalf("AdminIdentity() error = %v", err)
	}
	if ident.SSOSub != "sso-sub-123" || ident.SSOUsername != "admin_yoshi" || ident.SSOEmail != "admin@urlxl.com" || ident.SSOLinkedAt == 0 {
		t.Errorf("unexpected linked identity: %+v", ident)
	}

	if err := s.UnlinkAdminSSO(); err != nil {
		t.Fatalf("UnlinkAdminSSO() error = %v", err)
	}
	ident, _ = s.AdminIdentity()
	if ident.SSOSub != "" || ident.SSOUsername != "" {
		t.Errorf("expected empty SSO fields after unlink, got: %+v", ident)
	}

	// Test SSOSettings
	sso, err := s.SSOSettings()
	if err != nil {
		t.Fatalf("SSOSettings() error = %v", err)
	}
	if sso.Enabled {
		t.Error("expected SSO initially disabled")
	}

	sso.Enabled = true
	sso.IssuerURL = "https://auth.urlxl.com"
	sso.ClientID = "kydns-client"
	if err := s.SetSSOSettings(sso); err != nil {
		t.Fatalf("SetSSOSettings error = %v", err)
	}

	ssoGot, err := s.SSOSettings()
	if err != nil || !ssoGot.Enabled || ssoGot.IssuerURL != "https://auth.urlxl.com" || ssoGot.ClientID != "kydns-client" {
		t.Errorf("unexpected SSOSettings: %+v, err: %v", ssoGot, err)
	}
}
