package registry

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateLabel(t *testing.T) {
	valid := []string{"a", "kypost", "web-mail", "n1", strings.Repeat("x", 63)}
	invalid := []string{"", "-lead", "trail-", "under_score", "has.dot", strings.Repeat("x", 64), "UPPER!"}
	for _, s := range valid {
		if err := ValidateLabel(s); err != nil {
			t.Errorf("ValidateLabel(%q) = %v, want nil", s, err)
		}
	}
	for _, s := range invalid {
		if err := ValidateLabel(s); err == nil {
			t.Errorf("ValidateLabel(%q) = nil, want error", s)
		}
	}
}

func TestValidateNameRequiresPrivateDomain(t *testing.T) {
	const zone = "home.arpa."
	if err := ValidateName("kypost.home.arpa.", zone); err != nil {
		t.Errorf("in-zone name rejected: %v", err)
	}
	if err := ValidateName("kypost.example.com.", zone); err == nil {
		t.Error("out-of-zone name accepted, want error")
	}
	if err := ValidateName("home.arpa.", zone); err == nil {
		t.Error("bare apex accepted, want error")
	}
	if err := ValidateName("*.home.arpa.", zone); err == nil {
		t.Error("wildcard accepted, want error")
	}
}

func TestNormalize(t *testing.T) {
	for in, want := range map[string]string{
		"KyPost.Home.Arpa":  "kypost.home.arpa.",
		"kypost.home.arpa.": "kypost.home.arpa.",
	} {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValidateAddress(t *testing.T) {
	for _, s := range []string{"192.168.1.20", "100.101.102.103", "fd00::1"} {
		if err := ValidateAddress(s); err != nil {
			t.Errorf("ValidateAddress(%q) = %v, want nil", s, err)
		}
	}
	for _, s := range []string{"", "192.168.1", "not-an-ip", "192.168.1.20/24"} {
		if err := ValidateAddress(s); err == nil {
			t.Errorf("ValidateAddress(%q) = nil, want error", s)
		}
	}
}

func TestValidateRecordType(t *testing.T) {
	for _, s := range []string{"A", "AAAA", "CNAME", "PTR"} {
		if err := ValidateRecordType(s); err != nil {
			t.Errorf("ValidateRecordType(%q) = %v, want nil", s, err)
		}
	}
	for _, s := range []string{"TXT", "MX", "SRV", "", "a"} {
		if err := ValidateRecordType(s); err == nil {
			t.Errorf("ValidateRecordType(%q) = nil, want error", s)
		}
	}
}

// The error must name the offending field so the CLI and the UI render the
// same failure.
func TestValidationErrorCarriesField(t *testing.T) {
	err := ValidateAddress("nope")
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("error %v is not a *ValidationError", err)
	}
	if ve.Field != "address" || ve.Code == "" {
		t.Errorf("Field = %q, Code = %q, want both populated", ve.Field, ve.Code)
	}
}
