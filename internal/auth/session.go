package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"sync"
	"time"
)

// CookieName is the session cookie. It is set HttpOnly and SameSite=Lax, and
// Secure whenever the request arrived over TLS.
const CookieName = "kydns_session"

type Session struct {
	ID       string
	CSRF     string
	Created  time.Time
	LastSeen time.Time
}

// Sessions is an in-memory session store. Restart forces re-login, which is
// the deliberate trade: session state never touches the database or backups,
// and a homelab DNS server restarts rarely.
type Sessions struct {
	mu       sync.Mutex
	byID     map[string]*Session
	idle     time.Duration
	absolute time.Duration
	now      func() time.Time
}

func NewSessions(idle, absolute time.Duration) *Sessions {
	return &Sessions{
		byID: map[string]*Session{}, idle: idle, absolute: absolute, now: time.Now,
	}
}

func randomHex(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(buf)
}

func (s *Sessions) Create() *Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	sess := &Session{ID: randomHex(32), CSRF: randomHex(32), Created: now, LastSeen: now}
	s.byID[sess.ID] = sess
	return sess
}

// Get returns a live session and slides its idle window. Both the idle and
// absolute deadlines are enforced here so there is one expiry path, and an
// expired session is dropped rather than merely hidden.
func (s *Sessions) Get(id string) (*Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.byID[id]
	if !ok {
		return nil, false
	}
	now := s.now()
	if now.Sub(sess.LastSeen) > s.idle || now.Sub(sess.Created) > s.absolute {
		delete(s.byID, id)
		return nil, false
	}
	sess.LastSeen = now
	return sess, true
}

func (s *Sessions) Destroy(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.byID, id)
}

func (s *Sessions) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.byID)
}

// ValidCSRF checks a form token against its own session, in constant time.
func (s *Sessions) ValidCSRF(id, token string) bool {
	sess, ok := s.Get(id)
	if !ok || token == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(sess.CSRF), []byte(token)) == 1
}
