// Package auth handles operator authentication: password hashing, login
// backoff, and sessions.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

// argon2id parameters. Tuned for a homelab box: roughly 64 MiB and a few tens
// of milliseconds, which is ample for an interactive login and painful for an
// offline attacker.
const (
	argonMemory  = 64 * 1024 // KiB
	argonTime    = 3
	argonThreads = 2
	argonKeyLen  = 32
	argonSaltLen = 16
)

// HashPassword returns a PHC-format argon2id string that embeds its own
// parameters, so raising the cost later does not invalidate old hashes.
func HashPassword(plaintext string) (string, error) {
	if plaintext == "" {
		return "", errors.New("password must not be empty")
	}
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(plaintext), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPassword compares in constant time. A malformed hash is a false, never
// a panic: a corrupted row must not crash the login page.
func VerifyPassword(encoded, plaintext string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false
	}
	var memory, times uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &times, &threads); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) == 0 {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(want) == 0 {
		return false
	}
	got := argon2.IDKey([]byte(plaintext), salt, times, memory, threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

const (
	backoffBase = 100 * time.Millisecond
	backoffCap  = 30 * time.Second
	// backoffMaxShift keeps the doubling from overflowing before the cap
	// clamps it. 2^18 * 100ms already far exceeds backoffCap.
	backoffMaxShift = 18
)

// Backoff slows repeated failed logins per source. It deliberately never
// locks an account: a permanent lockout hands an attacker a denial of service
// against the operator.
type Backoff struct {
	mu       sync.Mutex
	failures map[string]int
}

func NewBackoff() *Backoff { return &Backoff{failures: map[string]int{}} }

// Delay is how long to wait before answering the next attempt from key.
func (b *Backoff) Delay(key string) time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := b.failures[key]
	if n == 0 {
		return 0
	}
	if n > backoffMaxShift {
		return backoffCap
	}
	d := backoffBase << (n - 1)
	if d > backoffCap {
		return backoffCap
	}
	return d
}

func (b *Backoff) Fail(key string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.failures[key]++
}

func (b *Backoff) Reset(key string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.failures, key)
}
