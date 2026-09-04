package auth

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"
)

func TestHashAndVerify(t *testing.T) {
	h, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$") {
		t.Errorf("hash = %q, want a PHC argon2id string", h)
	}
	if strings.Contains(h, "correct horse") {
		t.Error("hash contains the plaintext")
	}
	if !VerifyPassword(h, "correct horse battery staple") {
		t.Error("VerifyPassword() rejected the correct password")
	}
	if VerifyPassword(h, "wrong") {
		t.Error("VerifyPassword() accepted the wrong password")
	}
}

// Distinct salts mean the same password hashes differently every time.
func TestHashIsSalted(t *testing.T) {
	a, _ := HashPassword("same")
	b, _ := HashPassword("same")
	if a == b {
		t.Error("two hashes of the same password are identical, want distinct salts")
	}
	if !VerifyPassword(a, "same") || !VerifyPassword(b, "same") {
		t.Error("salted hashes failed to verify")
	}
}

// A corrupted row must not crash the login page.
func TestVerifyRejectsMalformed(t *testing.T) {
	for _, h := range []string{
		"", "notahash", "$argon2id$v=19$broken", "$bcrypt$whatever",
		"$argon2id$v=19$m=64,t=1,p=1$notbase64!$alsonot!",
		"$argon2id$v=1$m=64,t=1,p=1$YWJj$YWJj",
	} {
		if VerifyPassword(h, "x") {
			t.Errorf("VerifyPassword(%q) = true, want false", h)
		}
	}
}

func TestHashRejectsEmptyPassword(t *testing.T) {
	if _, err := HashPassword(""); err == nil {
		t.Error("HashPassword(\"\") error = nil, want error")
	}
}

func TestVerifyAcceptsExistingKyDNSHash(t *testing.T) {
	// Reproduce the pre-shared-library KyDNS encoding (m=65536,t=3,p=2).
	const plaintext = "legacy password"
	salt := []byte("saltsaltsaltsalt")
	key := argon2.IDKey([]byte(plaintext), salt, 3, 64*1024, 2, 32)
	legacy := fmt.Sprintf("$argon2id$v=19$m=65536,t=3,p=2$%s$%s",
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key))
	if !VerifyPassword(legacy, plaintext) {
		t.Fatal("shared verifier rejected a legacy KyDNS password hash")
	}
}

// Backoff grows with consecutive failures and never becomes a permanent
// lockout, which would let an attacker deny the operator access.
func TestBackoffGrowsAndResets(t *testing.T) {
	b := NewBackoff()
	if d := b.Delay("1.2.3.4"); d != 0 {
		t.Errorf("first Delay() = %v, want 0", d)
	}
	b.Fail("1.2.3.4")
	first := b.Delay("1.2.3.4")
	if first <= 0 {
		t.Fatalf("Delay() after one failure = %v, want > 0", first)
	}
	b.Fail("1.2.3.4")
	if second := b.Delay("1.2.3.4"); second <= first {
		t.Errorf("Delay() = %v after two failures, want more than %v", second, first)
	}
	b.Reset("1.2.3.4")
	if d := b.Delay("1.2.3.4"); d != 0 {
		t.Errorf("Delay() after Reset() = %v, want 0", d)
	}
}

func TestBackoffIsCapped(t *testing.T) {
	b := NewBackoff()
	for i := 0; i < 200; i++ {
		b.Fail("1.2.3.4")
	}
	d := b.Delay("1.2.3.4")
	if d > 30*time.Second {
		t.Errorf("Delay() = %v, want a cap so the operator is never locked out", d)
	}
	if d <= 0 {
		t.Errorf("Delay() = %v after many failures, want a positive capped delay", d)
	}
}

func TestBackoffIsPerKey(t *testing.T) {
	b := NewBackoff()
	b.Fail("1.2.3.4")
	b.Fail("1.2.3.4")
	if d := b.Delay("5.6.7.8"); d != 0 {
		t.Errorf("Delay() for an unrelated source = %v, want 0", d)
	}
}
