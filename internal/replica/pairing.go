package replica

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"strings"
	"sync"
	"time"
)

// codeAlphabet is Crockford-ish base32 without padding: an operator reads this
// off one screen and types it into another, so I and O and their digit
// lookalikes stay out.
var codeEncoding = base32.NewEncoding("ABCDEFGHJKMNPQRSTVWXYZ0123456789").WithPadding(base32.NoPadding)

// NewPairingCode returns 80 bits of entropy. The code authorizes an
// enrollment rather than authenticating one, and it costs the operator one
// extra line to type once in a node's lifetime.
func NewPairingCode() (string, error) {
	b := make([]byte, 10)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return codeEncoding.EncodeToString(b), nil
}

// Invite is one outstanding pairing code.
type Invite struct {
	Code      string
	ExpiresAt time.Time
}

// InviteBook holds unredeemed codes in memory only. A restart cancels every
// outstanding invite, which is the right default: an invite is something an
// operator is using right now.
type InviteBook struct {
	mu  sync.Mutex
	ttl time.Duration
	now func() time.Time
	out map[string]time.Time
}

func NewInviteBook(ttl time.Duration, now func() time.Time) *InviteBook {
	return &InviteBook{ttl: ttl, now: now, out: map[string]time.Time{}}
}

func (b *InviteBook) Mint() (Invite, error) {
	code, err := NewPairingCode()
	if err != nil {
		return Invite{}, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	exp := b.now().Add(b.ttl)
	b.out[code] = exp
	return Invite{Code: code, ExpiresAt: exp}, nil
}

// Redeem consumes a code. It compares in constant time and against every
// outstanding entry, so the time it takes does not reveal how much of a guess
// was right.
func (b *InviteBook) Redeem(code string) bool {
	code = strings.ToUpper(strings.TrimSpace(code))
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	found := false
	for c, exp := range b.out {
		if now.After(exp) {
			delete(b.out, c)
			continue
		}
		if subtle.ConstantTimeCompare([]byte(c), []byte(code)) == 1 {
			found = true
			delete(b.out, c)
		}
	}
	return found
}
