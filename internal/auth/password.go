// Package auth handles operator authentication: password hashing, login
// backoff, and sessions.
package auth

import (
	"sync"
	"time"

	"github.com/Busness-app/ky-primitives/password"
)

// MinPasswordLen is the shortest admin password accepted, wherever one is
// set: the web setup form and the reset-password command both use it.
const MinPasswordLen = 12

// HashPassword returns a PHC-format argon2id string that embeds its own
// parameters, so raising the cost later does not invalidate old hashes.
func HashPassword(plaintext string) (string, error) {
	return password.Hash(plaintext)
}

// VerifyPassword compares in constant time. A malformed hash is a false, never
// a panic: a corrupted row must not crash the login page.
func VerifyPassword(encoded, plaintext string) bool {
	ok, err := password.Verify(plaintext, encoded)
	return err == nil && ok
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
