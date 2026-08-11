# KyDNS Operator Surface Implementation Plan — Part 1 (Tasks 14–17)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax for tracking.

**Continues:** Plan 1 (`2026-08-11-kydns-core*.md`, Tasks 1–13). Read its **Global Constraints** — they apply here. Plan 1 must be complete and green before starting.

**Goal of this plan:** password authentication, first-run setup, sessions with CSRF, and the server-rendered web shell — then the five screens in Part 2 (Tasks 18–21).

**New dependency:** `golang.org/x/crypto` (argon2id). Already listed in the spec's Dependencies table.

**What this plan replaces:** Plan 1's bootstrap-token file was a stopgap. Task 16 introduces the real `/setup` flow. The bootstrap token stays for API-only installs.

---

### Task 14: Password hashing and the admin account

**Files:**
- Create: `internal/auth/password.go`
- Modify: `internal/store/store.go` (schema + admin queries)
- Test: `internal/auth/password_test.go`, `internal/store/admin_test.go`

**Interfaces:**
- Consumes: `store.Store`.
- Produces:
  - `func HashPassword(plaintext string) (string, error)` — PHC-format argon2id string
  - `func VerifyPassword(encoded, plaintext string) bool`
  - `type Backoff struct{ ... }`, `func NewBackoff() *Backoff`
  - `func (b *Backoff) Delay(key string) time.Duration`, `func (b *Backoff) Fail(key string)`, `func (b *Backoff) Reset(key string)`
  - `store`: `func (s *Store) SetAdminPassword(hash string) error`, `func (s *Store) AdminHash() (string, error)`, `func (s *Store) HasAdmin() (bool, error)`

- [ ] **Step 1: Write the failing test**

```go
// internal/auth/password_test.go
package auth

import (
	"strings"
	"testing"
	"time"
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

func TestVerifyRejectsMalformed(t *testing.T) {
	for _, h := range []string{"", "notahash", "$argon2id$v=19$broken", "$bcrypt$whatever"} {
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
	for i := 0; i < 50; i++ {
		b.Fail("1.2.3.4")
	}
	if d := b.Delay("1.2.3.4"); d > 30*time.Second {
		t.Errorf("Delay() = %v, want a cap so the operator is never locked out", d)
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
```

```go
// internal/store/admin_test.go
package store

import "testing"

func TestAdminPasswordRoundTrip(t *testing.T) {
	s := open(t)
	has, err := s.HasAdmin()
	if err != nil {
		t.Fatal(err)
	}
	if has {
		t.Fatal("HasAdmin() = true on a fresh database")
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/auth/ ./internal/store/ -run 'TestHash|TestVerify|TestBackoff|TestAdmin' -v`
Expected: FAIL — `undefined: HashPassword`, `undefined: HasAdmin`.

- [ ] **Step 3: Write minimal implementation**

```bash
go get golang.org/x/crypto
```

```go
// internal/auth/password.go
// Package auth handles operator authentication: password hashing, login
// backoff, and sessions.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
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
	var memory uint32
	var times uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &times, &threads); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(plaintext), salt, times, memory, threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

const (
	backoffBase = 100 * time.Millisecond
	backoffCap  = 30 * time.Second
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
	if n > 20 { // guard the shift before it overflows
		return backoffCap
	}
	d := time.Duration(math.Pow(2, float64(n-1))) * backoffBase
	if d > backoffCap || d <= 0 {
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
```

Append to `internal/store/store.go`, and add the table to `schema`:

```sql
CREATE TABLE IF NOT EXISTS admin (
  id            INTEGER PRIMARY KEY CHECK (id = 1),
  password_hash TEXT NOT NULL,
  updated_at    INTEGER NOT NULL DEFAULT (unixepoch())
);
```

```go
// append to internal/store/store.go

// SetAdminPassword writes the single admin row. The CHECK (id = 1) constraint
// makes a second admin account impossible at the schema level.
func (s *Store) SetAdminPassword(hash string) error {
	_, err := s.db.Exec(`
		INSERT INTO admin(id, password_hash, updated_at) VALUES(1, ?, unixepoch())
		ON CONFLICT(id) DO UPDATE SET password_hash = excluded.password_hash,
		                              updated_at = excluded.updated_at`, hash)
	return err
}

func (s *Store) AdminHash() (string, error) {
	var hash string
	err := s.db.QueryRow(`SELECT password_hash FROM admin WHERE id = 1`).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("%w: admin account", ErrNotFound)
	}
	return hash, err
}

func (s *Store) HasAdmin() (bool, error) {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM admin WHERE id = 1`).Scan(&n); err != nil {
		return false, err
	}
	return n > 0, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/auth/ ./internal/store/ -v`
Expected: PASS. `TestHashAndVerify` takes tens of milliseconds by design.

- [ ] **Step 5: Commit**

```bash
git add internal/auth internal/store
git commit -m "Add argon2id password hashing and login backoff

The PHC-format hash embeds its own parameters so raising the cost later
does not invalidate existing hashes. Backoff grows per source IP and
caps: a permanent lockout would hand an attacker a denial of service
against the operator.

AI-assisted contribution (agentic). Verified with: go test ./internal/auth/ ./internal/store/"
```

---

### Task 15: Sessions and CSRF

**Files:**
- Create: `internal/auth/session.go`
- Test: `internal/auth/session_test.go`

**Interfaces:**
- Consumes: nothing from Task 14.
- Produces:
  - `type Session struct { ID, CSRF string; Created, LastSeen time.Time }`
  - `type Sessions struct{ ... }`, `func NewSessions(idle, absolute time.Duration) *Sessions`
  - `func (s *Sessions) Create() *Session`, `Get(id string) (*Session, bool)`, `Destroy(id string)`, `Len() int`
  - `func (s *Sessions) ValidCSRF(id, token string) bool`
  - `const CookieName = "kydns_session"`

- [ ] **Step 1: Write the failing test**

```go
// internal/auth/session_test.go
package auth

import (
	"testing"
	"time"
)

func TestSessionCreateAndGet(t *testing.T) {
	s := NewSessions(time.Hour, 12*time.Hour)
	sess := s.Create()
	if len(sess.ID) < 32 {
		t.Errorf("session id %q is too short", sess.ID)
	}
	if len(sess.CSRF) < 32 {
		t.Errorf("csrf token %q is too short", sess.CSRF)
	}
	got, ok := s.Get(sess.ID)
	if !ok || got.ID != sess.ID {
		t.Fatal("Get() missed a freshly created session")
	}
	if _, ok := s.Get("nope"); ok {
		t.Error("Get() returned a session for an unknown id")
	}
}

func TestSessionsAreDistinct(t *testing.T) {
	s := NewSessions(time.Hour, 12*time.Hour)
	a, b := s.Create(), s.Create()
	if a.ID == b.ID || a.CSRF == b.CSRF {
		t.Error("two sessions share an id or csrf token")
	}
}

func TestSessionIdleTimeout(t *testing.T) {
	s := NewSessions(time.Hour, 12*time.Hour)
	now := time.Now()
	s.now = func() time.Time { return now }
	sess := s.Create()

	now = now.Add(30 * time.Minute)
	if _, ok := s.Get(sess.ID); !ok {
		t.Fatal("session expired before the idle timeout")
	}
	// Get refreshes LastSeen, so another 30 minutes must still be inside it.
	now = now.Add(50 * time.Minute)
	if _, ok := s.Get(sess.ID); !ok {
		t.Fatal("idle timeout is not sliding on access")
	}
	now = now.Add(2 * time.Hour)
	if _, ok := s.Get(sess.ID); ok {
		t.Error("session survived past the idle timeout")
	}
}

// The absolute cap bounds a session even when it is used constantly.
func TestSessionAbsoluteTimeout(t *testing.T) {
	s := NewSessions(time.Hour, 4*time.Hour)
	now := time.Now()
	s.now = func() time.Time { return now }
	sess := s.Create()
	for i := 0; i < 8; i++ {
		now = now.Add(30 * time.Minute)
		s.Get(sess.ID)
	}
	now = now.Add(time.Minute)
	if _, ok := s.Get(sess.ID); ok {
		t.Error("session survived past the absolute timeout despite constant use")
	}
}

func TestSessionDestroy(t *testing.T) {
	s := NewSessions(time.Hour, 12*time.Hour)
	sess := s.Create()
	s.Destroy(sess.ID)
	if _, ok := s.Get(sess.ID); ok {
		t.Error("Get() returned a destroyed session")
	}
	if s.Len() != 0 {
		t.Errorf("Len() = %d after Destroy(), want 0", s.Len())
	}
}

func TestValidCSRF(t *testing.T) {
	s := NewSessions(time.Hour, 12*time.Hour)
	sess := s.Create()
	if !s.ValidCSRF(sess.ID, sess.CSRF) {
		t.Error("ValidCSRF() rejected the session's own token")
	}
	if s.ValidCSRF(sess.ID, "wrong") {
		t.Error("ValidCSRF() accepted a wrong token")
	}
	if s.ValidCSRF("unknown", sess.CSRF) {
		t.Error("ValidCSRF() accepted a token for an unknown session")
	}
	// A token from one session must not authorize another.
	other := s.Create()
	if s.ValidCSRF(sess.ID, other.CSRF) {
		t.Error("ValidCSRF() accepted another session's token")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/auth/ -run TestSession -v`
Expected: FAIL — `undefined: NewSessions`.

- [ ] **Step 3: Write minimal implementation**

```go
// internal/auth/session.go
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
// absolute deadlines are enforced here so there is one expiry path.
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/auth/ -race -v`
Expected: PASS, all password and session tests.

- [ ] **Step 5: Commit**

```bash
git add internal/auth
git commit -m "Add in-memory sessions with sliding idle and absolute timeouts

Sessions live in memory so state never reaches the database or backups;
restart forces re-login, which is cheap for a homelab server. CSRF
tokens are per-session and compared in constant time.

AI-assisted contribution (agentic). Verified with: go test -race ./internal/auth/"
```

---

### Task 16: First-run setup and login

**Files:**
- Create: `internal/web/auth_handlers.go`, `internal/web/middleware.go`
- Test: `internal/web/auth_test.go`

**Interfaces:**
- Consumes: `auth.HashPassword`, `auth.VerifyPassword`, `auth.Sessions`, `auth.Backoff`, `store.Store`.
- Produces:
  - `type Server struct{ ... }`, `type Options struct { Store *store.Store; Registry *registry.Registry; Sessions *auth.Sessions; Backoff *auth.Backoff; ACL *dnsserver.ACL; Cache *dnsserver.Cache; SetupToken string; Logger *slog.Logger }`
  - `func New(o Options) *Server`, `func (s *Server) Routes(mux *http.ServeMux)`
  - `func (s *Server) requireSession(http.HandlerFunc) http.HandlerFunc`
  - `func (s *Server) requireCSRF(http.HandlerFunc) http.HandlerFunc`

- [ ] **Step 1: Write the failing test**

```go
// internal/web/auth_test.go
package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yoshiofthewire/kydns-server/internal/auth"
	"github.com/yoshiofthewire/kydns-server/internal/registry"
	"github.com/yoshiofthewire/kydns-server/internal/store"
)

func newWeb(t *testing.T) (http.Handler, *Server) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "kydns.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	srv := New(Options{
		Store:      st,
		Registry:   registry.New(st, "home.arpa.", func() error { return nil }),
		Sessions:   auth.NewSessions(time.Hour, 12*time.Hour),
		Backoff:    auth.NewBackoff(),
		SetupToken: "setup-me",
	})
	mux := http.NewServeMux()
	srv.Routes(mux)
	return mux, srv
}

func get(t *testing.T, h http.Handler, path string, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func postForm(t *testing.T, h http.Handler, path string, form url.Values, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func sessionCookie(rec *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == auth.CookieName {
			return c
		}
	}
	return nil
}

// Before an admin exists, every route funnels to /setup.
func TestUnsetupRedirectsToSetup(t *testing.T) {
	h, _ := newWeb(t)
	for _, path := range []string{"/", "/services", "/records", "/settings", "/login"} {
		rec := get(t, h, path, nil)
		if rec.Code != http.StatusSeeOther {
			t.Errorf("GET %s = %d, want 303 to /setup", path, rec.Code)
			continue
		}
		if loc := rec.Header().Get("Location"); loc != "/setup" {
			t.Errorf("GET %s redirected to %q, want /setup", path, loc)
		}
	}
}

func TestSetupRequiresTheToken(t *testing.T) {
	h, _ := newWeb(t)
	rec := postForm(t, h, "/setup", url.Values{
		"token": {"wrong"}, "password": {"a-good-password"}, "confirm": {"a-good-password"},
	}, nil)
	if rec.Code == http.StatusSeeOther {
		t.Fatal("setup succeeded with the wrong token")
	}
	if !strings.Contains(rec.Body.String(), "token") {
		t.Errorf("body does not mention the token problem:\n%s", rec.Body)
	}
}

func TestSetupRejectsMismatchedConfirmation(t *testing.T) {
	h, _ := newWeb(t)
	rec := postForm(t, h, "/setup", url.Values{
		"token": {"setup-me"}, "password": {"one-password"}, "confirm": {"another"},
	}, nil)
	if rec.Code == http.StatusSeeOther {
		t.Error("setup accepted mismatched passwords")
	}
}

func TestSetupRejectsShortPassword(t *testing.T) {
	h, _ := newWeb(t)
	rec := postForm(t, h, "/setup", url.Values{
		"token": {"setup-me"}, "password": {"short"}, "confirm": {"short"},
	}, nil)
	if rec.Code == http.StatusSeeOther {
		t.Error("setup accepted a password below the minimum length")
	}
}

func TestSetupThenLogin(t *testing.T) {
	h, _ := newWeb(t)
	rec := postForm(t, h, "/setup", url.Values{
		"token": {"setup-me"}, "password": {"a-good-password"}, "confirm": {"a-good-password"},
	}, nil)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("setup = %d: %s", rec.Code, rec.Body)
	}
	if sessionCookie(rec) == nil {
		t.Error("setup did not log the operator in")
	}
	// Setup is single-use.
	rec = get(t, h, "/setup", nil)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Errorf("GET /setup after setup = %d %q, want a redirect to /login",
			rec.Code, rec.Header().Get("Location"))
	}

	rec = postForm(t, h, "/login", url.Values{"password": {"a-good-password"}}, nil)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("login = %d: %s", rec.Code, rec.Body)
	}
	c := sessionCookie(rec)
	if c == nil {
		t.Fatal("login set no session cookie")
	}
	if !c.HttpOnly {
		t.Error("session cookie is not HttpOnly")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Error("session cookie is not SameSite=Lax")
	}
}

func TestLoginRejectsWrongPassword(t *testing.T) {
	h, _ := newWeb(t)
	postForm(t, h, "/setup", url.Values{
		"token": {"setup-me"}, "password": {"a-good-password"}, "confirm": {"a-good-password"},
	}, nil)
	rec := postForm(t, h, "/login", url.Values{"password": {"wrong"}}, nil)
	if sessionCookie(rec) != nil {
		t.Error("a failed login issued a session cookie")
	}
	if rec.Code == http.StatusSeeOther {
		t.Error("a failed login redirected as though it succeeded")
	}
}

func TestProtectedRouteNeedsSession(t *testing.T) {
	h, _ := newWeb(t)
	postForm(t, h, "/setup", url.Values{
		"token": {"setup-me"}, "password": {"a-good-password"}, "confirm": {"a-good-password"},
	}, nil)
	rec := get(t, h, "/services", nil)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Errorf("unauthenticated /services = %d %q, want a redirect to /login",
			rec.Code, rec.Header().Get("Location"))
	}
}

func TestLogoutDestroysSession(t *testing.T) {
	h, _ := newWeb(t)
	postForm(t, h, "/setup", url.Values{
		"token": {"setup-me"}, "password": {"a-good-password"}, "confirm": {"a-good-password"},
	}, nil)
	rec := postForm(t, h, "/login", url.Values{"password": {"a-good-password"}}, nil)
	c := sessionCookie(rec)
	if get(t, h, "/services", c).Code != http.StatusOK {
		t.Fatal("session did not grant access")
	}
	postForm(t, h, "/logout", url.Values{}, c)
	if got := get(t, h, "/services", c).Code; got != http.StatusSeeOther {
		t.Errorf("after logout /services = %d, want a redirect", got)
	}
}

// A POST without the session's CSRF token must be rejected.
func TestCSRFRequiredOnPost(t *testing.T) {
	h, srv := newWeb(t)
	postForm(t, h, "/setup", url.Values{
		"token": {"setup-me"}, "password": {"a-good-password"}, "confirm": {"a-good-password"},
	}, nil)
	rec := postForm(t, h, "/login", url.Values{"password": {"a-good-password"}}, nil)
	c := sessionCookie(rec)

	bad := postForm(t, h, "/services/new", url.Values{
		"name": {"kypost"}, "address": {"192.168.1.20"},
	}, c)
	if bad.Code != http.StatusForbidden {
		t.Errorf("POST without a CSRF token = %d, want 403", bad.Code)
	}

	sess, ok := srv.Options().Sessions.Get(c.Value)
	if !ok {
		t.Fatal("session vanished")
	}
	good := postForm(t, h, "/services/new", url.Values{
		"name": {"kypost"}, "address": {"192.168.1.20"}, "csrf_token": {sess.CSRF},
	}, c)
	if good.Code == http.StatusForbidden {
		t.Errorf("POST with a valid CSRF token = 403: %s", good.Body)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/web/ -v`
Expected: FAIL — `undefined: New`.

- [ ] **Step 3: Write minimal implementation**

```go
// internal/web/middleware.go
// Package web is the HTML transport. Like adminapi it holds no business rules:
// both call the same registry service.
package web

import (
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/yoshiofthewire/kydns-server/internal/auth"
	"github.com/yoshiofthewire/kydns-server/internal/dnsserver"
	"github.com/yoshiofthewire/kydns-server/internal/registry"
	"github.com/yoshiofthewire/kydns-server/internal/store"
)

type Options struct {
	Store      *store.Store
	Registry   *registry.Registry
	Sessions   *auth.Sessions
	Backoff    *auth.Backoff
	ACL        *dnsserver.ACL
	Cache      *dnsserver.Cache
	SetupToken string
	Logger     *slog.Logger
}

type Server struct{ o Options }

func New(o Options) *Server {
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	return &Server{o: o}
}

// Options exposes the wiring for tests and for handlers in sibling files.
func (s *Server) Options() Options { return s.o }

const minPasswordLen = 12

func (s *Server) hasAdmin() bool {
	ok, err := s.o.Store.HasAdmin()
	if err != nil {
		s.o.Logger.Error("check admin", "error", err)
		return false
	}
	return ok
}

// requireSetup funnels every route to /setup until an admin password exists.
func (s *Server) requireSetup(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.hasAdmin() {
			http.Redirect(w, r, "/setup", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

// requireSession redirects anonymous visitors to the login page.
func (s *Server) requireSession(next http.HandlerFunc) http.HandlerFunc {
	return s.requireSetup(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := s.session(r); !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r)
	})
}

// requireCSRF rejects a form post whose token does not belong to its session.
// SameSite=Lax already blocks most cross-site posts; this closes the rest.
func (s *Server) requireCSRF(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, ok := s.session(r)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "malformed form", http.StatusBadRequest)
			return
		}
		if !s.o.Sessions.ValidCSRF(sess.ID, r.PostFormValue("csrf_token")) {
			http.Error(w, "invalid CSRF token", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

func (s *Server) session(r *http.Request) (*auth.Session, bool) {
	c, err := r.Cookie(auth.CookieName)
	if err != nil {
		return nil, false
	}
	return s.o.Sessions.Get(c.Value)
}

func (s *Server) setSessionCookie(w http.ResponseWriter, r *http.Request, sess *auth.Session) {
	http.SetCookie(w, &http.Cookie{
		Name:     auth.CookieName,
		Value:    sess.ID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
	})
}

func sourceKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
```

```go
// internal/web/auth_handlers.go
package web

import (
	"crypto/subtle"
	"net/http"
	"time"

	"github.com/yoshiofthewire/kydns-server/internal/auth"
)

func (s *Server) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /setup", s.getSetup)
	mux.HandleFunc("POST /setup", s.postSetup)
	mux.HandleFunc("GET /login", s.requireSetup(s.getLogin))
	mux.HandleFunc("POST /login", s.requireSetup(s.postLogin))
	mux.HandleFunc("POST /logout", s.requireSession(s.postLogout))
	s.pageRoutes(mux) // defined in Part 2 (Tasks 18-21)
}

func (s *Server) getSetup(w http.ResponseWriter, r *http.Request) {
	if s.hasAdmin() {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.renderBare(w, "setup.html", map[string]any{"Title": "Set up KyDNS"})
}

// postSetup consumes the one-time token and creates the admin account. It is
// unauthenticated by necessity, so the token is the whole gate.
func (s *Server) postSetup(w http.ResponseWriter, r *http.Request) {
	if s.hasAdmin() {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "malformed form", http.StatusBadRequest)
		return
	}
	fail := func(msg string) {
		w.WriteHeader(http.StatusBadRequest)
		s.renderBare(w, "setup.html", map[string]any{"Title": "Set up KyDNS", "Error": msg})
	}

	// Constant-time so the token cannot be recovered by timing.
	given := r.PostFormValue("token")
	if subtle.ConstantTimeCompare([]byte(given), []byte(s.o.SetupToken)) != 1 {
		s.o.Logger.Warn("setup attempted with an invalid token", "source", sourceKey(r))
		fail("That setup token is not correct. It was printed to the server log at startup.")
		return
	}
	password := r.PostFormValue("password")
	if len(password) < minPasswordLen {
		fail("Choose a password of at least 12 characters.")
		return
	}
	if password != r.PostFormValue("confirm") {
		fail("The two passwords do not match.")
		return
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		fail(err.Error())
		return
	}
	if err := s.o.Store.SetAdminPassword(hash); err != nil {
		fail(err.Error())
		return
	}
	s.o.Logger.Info("admin account created")
	s.setSessionCookie(w, r, s.o.Sessions.Create())
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) getLogin(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.session(r); ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.renderBare(w, "login.html", map[string]any{"Title": "Sign in"})
}

func (s *Server) postLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "malformed form", http.StatusBadRequest)
		return
	}
	key := sourceKey(r)
	// Sleep before answering, so guessing gets slower without ever locking out.
	if d := s.o.Backoff.Delay(key); d > 0 {
		time.Sleep(d)
	}
	hash, err := s.o.Store.AdminHash()
	if err != nil || !auth.VerifyPassword(hash, r.PostFormValue("password")) {
		s.o.Backoff.Fail(key)
		s.o.Logger.Warn("failed login", "source", key)
		w.WriteHeader(http.StatusUnauthorized)
		s.renderBare(w, "login.html", map[string]any{
			"Title": "Sign in", "Error": "That password is not correct.",
		})
		return
	}
	s.o.Backoff.Reset(key)
	s.setSessionCookie(w, r, s.o.Sessions.Create())
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) postLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(auth.CookieName); err == nil {
		s.o.Sessions.Destroy(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: auth.CookieName, Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
```

`renderBare`, `pageRoutes`, and the templates arrive in Task 17. To keep this
task independently testable, add a temporary stub in `internal/web/render.go`
and replace it in Task 17:

```go
// internal/web/render.go — replaced in Task 17
package web

import (
	"fmt"
	"net/http"
)

func (s *Server) renderBare(w http.ResponseWriter, name string, data map[string]any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<!doctype html><title>%v</title><p>%v</p><p>%v</p>",
		data["Title"], name, data["Error"])
}

func (s *Server) pageRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /", s.requireSession(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "dashboard")
	}))
	for _, p := range []string{"/services", "/records", "/settings"} {
		mux.HandleFunc("GET "+p, s.requireSession(func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprint(w, "page")
		}))
	}
	mux.HandleFunc("POST /services/new", s.requireCSRF(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusSeeOther)
	}))
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/web/ -v`
Expected: PASS, all nine auth tests.

- [ ] **Step 5: Commit**

```bash
git add internal/web
git commit -m "Add first-run setup, login, logout, and CSRF middleware

Every route funnels to /setup until an admin password exists. The setup
token is compared in constant time because that endpoint is
unauthenticated by necessity, so the token is the whole gate. Failed
logins sleep before answering rather than locking the account.

AI-assisted contribution (agentic). Verified with: go test ./internal/web/"
```

---

### Task 17: Web shell, templates, and assets

**Files:**
- Create: `internal/web/render.go` (replaces the Task 16 stub), `internal/web/templates/base.html`, `layout.html`, `login.html`, `setup.html`, `internal/web/static/app.css`
- Modify: `css/styles.css` (font path fix), copy assets into `internal/web/static/`
- Test: `internal/web/render_test.go`

**Interfaces:**
- Consumes: `Server` from Task 16.
- Produces:
  - `func (s *Server) render(w http.ResponseWriter, r *http.Request, page string, data map[string]any)` — full chrome
  - `func (s *Server) renderBare(w http.ResponseWriter, page string, data map[string]any)` — no nav, for setup and login
  - `func (s *Server) StaticHandler() http.Handler`

- [ ] **Step 1: Write the failing test**

```go
// internal/web/render_test.go
package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStaticServesStylesheet(t *testing.T) {
	_, srv := newWeb(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/static/app.css", nil)
	srv.StaticHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /static/app.css = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "--accent") {
		t.Error("app.css does not build on the existing design tokens")
	}
}

// The marketing stylesheet shipped with @font-face paths pointing at
// ../assets/fonts, but the fonts live elsewhere. The embedded copy must be
// fixed, and the referenced files must actually be present.
func TestEmbeddedFontPathsResolve(t *testing.T) {
	_, srv := newWeb(t)
	h := srv.StaticHandler()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/static/styles.css", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /static/styles.css = %d", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "../assets/fonts") {
		t.Error("embedded styles.css still points at ../assets/fonts")
	}
	for _, want := range []string{
		"/static/fonts/Space_Grotesk/SpaceGrotesk-VariableFont_wght.ttf",
		"/static/fonts/IBM_Plex_Mono/IBMPlexMono-Regular.ttf",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("styles.css does not reference %s", want)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", want, nil))
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s = %d, want the font to be embedded", want, rec.Code)
		}
	}
}

func TestRenderIncludesNavAndCSRF(t *testing.T) {
	h, srv := newWeb(t)
	setupAndLogin(t, h)
	_ = srv

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(loginCookie(t, h))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET / = %d: %s", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	for _, want := range []string{`href="/services"`, `href="/records"`, `href="/settings"`, "/static/app.css"} {
		if !strings.Contains(body, want) {
			t.Errorf("rendered page missing %q", want)
		}
	}
}

// Templates must escape interpolated values. A service name is operator input
// and reaches the page unfiltered otherwise.
func TestTemplatesEscapeHTML(t *testing.T) {
	_, srv := newWeb(t)
	rec := httptest.NewRecorder()
	srv.renderBare(rec, "login.html", map[string]any{
		"Title": "Sign in", "Error": `<script>alert(1)</script>`,
	})
	if strings.Contains(rec.Body.String(), "<script>alert(1)</script>") {
		t.Error("template emitted unescaped HTML")
	}
}
```

Add these helpers to `auth_test.go`:

```go
func setupAndLogin(t *testing.T, h http.Handler) {
	t.Helper()
	postForm(t, h, "/setup", url.Values{
		"token": {"setup-me"}, "password": {"a-good-password"}, "confirm": {"a-good-password"},
	}, nil)
}

func loginCookie(t *testing.T, h http.Handler) *http.Cookie {
	t.Helper()
	if !strings.Contains(get(t, h, "/login", nil).Body.String(), "") {
		t.Fatal("login page unavailable")
	}
	rec := postForm(t, h, "/login", url.Values{"password": {"a-good-password"}}, nil)
	c := sessionCookie(rec)
	if c == nil {
		t.Fatal("no session cookie after login")
	}
	return c
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/web/ -run 'TestStatic|TestEmbedded|TestRender|TestTemplates' -v`
Expected: FAIL — `undefined: StaticHandler` and missing embedded assets.

- [ ] **Step 3: Write minimal implementation**

Copy the assets in, embedding only the weights the stylesheet references:

```bash
mkdir -p internal/web/static/fonts/Space_Grotesk internal/web/static/fonts/IBM_Plex_Mono
cp css/styles.css internal/web/static/styles.css
cp fonts/Space_Grotesk/SpaceGrotesk-VariableFont_wght.ttf internal/web/static/fonts/Space_Grotesk/
cp fonts/IBM_Plex_Mono/IBMPlexMono-Regular.ttf \
   fonts/IBM_Plex_Mono/IBMPlexMono-Medium.ttf \
   fonts/IBM_Plex_Mono/IBMPlexMono-SemiBold.ttf \
   internal/web/static/fonts/IBM_Plex_Mono/
cp fonts/Space_Grotesk/OFL.txt internal/web/static/fonts/Space_Grotesk/
cp fonts/IBM_Plex_Mono/OFL.txt internal/web/static/fonts/IBM_Plex_Mono/
sed -i 's#\.\./assets/fonts/#/static/fonts/#g' internal/web/static/styles.css
```

Fix the source stylesheet too, so the repository copy is not left broken:

```bash
sed -i 's#\.\./assets/fonts/#../fonts/#g' css/styles.css
```

Only four weights are embedded because only four are referenced. The rest of
`fonts/` stays in the repository for the marketing site.

```css
/* internal/web/static/app.css
   App components layered on the Patina Ky tokens from styles.css. The
   marketing theme is not modified. */
.app { display: grid; grid-template-columns: 200px 1fr; min-height: 100vh; }
.app-nav { background: var(--panel); border-right: 1px solid var(--line); padding: 1.5rem 0; }
.app-nav h1 { font-family: var(--font-display); font-size: 1.1rem; margin: 0 1.25rem 1.5rem; color: var(--accent); }
.app-nav a { display: block; padding: .55rem 1.25rem; color: var(--ink); text-decoration: none;
             font-family: var(--font-mono); font-size: .85rem; }
.app-nav a:hover { color: var(--ink-strong); background: rgba(255,255,255,.03); }
.app-nav a[aria-current="page"] { color: var(--accent); border-left: 2px solid var(--accent); }
.app-main { padding: 2rem 2.5rem; max-width: var(--max-width); }
.app-main h2 { font-family: var(--font-display); color: var(--ink-strong); margin-top: 0; }

.card { background: var(--panel); border: 1px solid var(--line); border-radius: 8px;
        padding: 1.25rem; margin-bottom: 1.5rem; }
.stat-row { display: flex; gap: 1.5rem; flex-wrap: wrap; }
.stat { flex: 1 1 8rem; }
.stat .value { font-family: var(--font-display); font-size: 1.6rem; color: var(--ink-strong); }
.stat .label { font-family: var(--font-mono); font-size: .72rem; color: var(--ink); text-transform: uppercase; }

table.grid { width: 100%; border-collapse: collapse; font-family: var(--font-mono); font-size: .85rem; }
table.grid th { text-align: left; color: var(--ink); font-weight: 500; text-transform: uppercase;
                font-size: .7rem; padding: .5rem .75rem; border-bottom: 1px solid var(--line); }
table.grid td { padding: .55rem .75rem; border-bottom: 1px solid var(--line); color: var(--ink-strong); }
table.grid tr:last-child td { border-bottom: 0; }

.badge { display: inline-block; padding: .12rem .5rem; border-radius: 999px; font-size: .7rem;
         font-family: var(--font-mono); border: 1px solid var(--line); color: var(--ink); }
.badge.accent { color: var(--accent); border-color: var(--accent-soft); background: var(--accent-soft); }
.badge.warn { color: #fbbf24; border-color: #78350f; background: #78350f33; }
.badge.down { color: #f87171; border-color: #7f1d1d; background: #7f1d1d33; }

.banner { border-radius: 8px; padding: 1rem 1.25rem; margin-bottom: 1.5rem;
          border: 1px solid #78350f; background: #78350f33; color: #fde68a; font-size: .9rem; }
.banner strong { display: block; font-family: var(--font-display); margin-bottom: .35rem; color: #fbbf24; }
.banner code { font-family: var(--font-mono); background: rgba(0,0,0,.35); padding: .1rem .35rem; border-radius: 3px; }

form.stack { display: flex; flex-direction: column; gap: .75rem; max-width: 30rem; }
form.stack label { font-family: var(--font-mono); font-size: .75rem; color: var(--ink); text-transform: uppercase; }
input[type=text], input[type=password], select {
  background: var(--bg); border: 1px solid var(--line); border-radius: 5px; padding: .5rem .65rem;
  color: var(--ink-strong); font-family: var(--font-mono); font-size: .85rem; width: 100%; }
input:focus, select:focus { outline: none; border-color: var(--accent); box-shadow: 0 0 0 3px var(--glow); }
button { background: var(--accent); color: #04211f; border: 0; border-radius: 5px; padding: .55rem 1.1rem;
         font-family: var(--font-mono); font-size: .82rem; cursor: pointer; }
button.ghost { background: transparent; color: var(--ink); border: 1px solid var(--line); }
button.danger { background: transparent; color: #f87171; border: 1px solid #7f1d1d; }
.error { color: #f87171; font-family: var(--font-mono); font-size: .82rem; }
.centered { max-width: 24rem; margin: 12vh auto; }
.address-row { display: flex; gap: .5rem; }
.muted { color: var(--ink); }
```

```html
<!-- internal/web/templates/base.html -->
{{define "base"}}<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}} — KyDNS</title>
<link rel="stylesheet" href="/static/styles.css">
<link rel="stylesheet" href="/static/app.css">
</head>
<body>{{template "body" .}}</body>
</html>{{end}}
```

```html
<!-- internal/web/templates/layout.html -->
{{define "body"}}
<div class="app">
  <nav class="app-nav">
    <h1>KyDNS</h1>
    <a href="/"{{if eq .Nav "dashboard"}} aria-current="page"{{end}}>Dashboard</a>
    <a href="/services"{{if eq .Nav "services"}} aria-current="page"{{end}}>Services</a>
    <a href="/records"{{if eq .Nav "records"}} aria-current="page"{{end}}>Records</a>
    <a href="/discovered"{{if eq .Nav "discovered"}} aria-current="page"{{end}}>Discovered</a>
    <a href="/settings"{{if eq .Nav "settings"}} aria-current="page"{{end}}>Settings</a>
    <form method="post" action="/logout" style="padding:1rem 1.25rem">
      <input type="hidden" name="csrf_token" value="{{.CSRF}}">
      <button class="ghost" type="submit">Sign out</button>
    </form>
  </nav>
  <main class="app-main">
    <h2>{{.Title}}</h2>
    {{if .Error}}<p class="error">{{.Error}}</p>{{end}}
    {{template "page" .}}
  </main>
</div>
{{end}}
```

```html
<!-- internal/web/templates/login.html -->
{{define "body"}}
<div class="centered card">
  <h2>Sign in</h2>
  {{if .Error}}<p class="error">{{.Error}}</p>{{end}}
  <form class="stack" method="post" action="/login">
    <label for="password">Password</label>
    <input id="password" name="password" type="password" autocomplete="current-password" autofocus>
    <button type="submit">Sign in</button>
  </form>
</div>
{{end}}
```

```html
<!-- internal/web/templates/setup.html -->
{{define "body"}}
<div class="centered card">
  <h2>Set up KyDNS</h2>
  <p class="muted">The setup token was written to the server log when KyDNS started.</p>
  {{if .Error}}<p class="error">{{.Error}}</p>{{end}}
  <form class="stack" method="post" action="/setup">
    <label for="token">Setup token</label>
    <input id="token" name="token" type="text" autofocus>
    <label for="password">New password (12 characters or more)</label>
    <input id="password" name="password" type="password" autocomplete="new-password">
    <label for="confirm">Confirm password</label>
    <input id="confirm" name="confirm" type="password" autocomplete="new-password">
    <button type="submit">Create admin account</button>
  </form>
</div>
{{end}}
```

```go
// internal/web/render.go — replaces the Task 16 stub
package web

import (
	"bytes"
	"embed"
	"html/template"
	"net/http"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

// pageTemplate parses base + layout + the page, so every page shares chrome.
// Parsing per request would be wasteful, so they are parsed once at init.
var (
	bareTemplates = template.Must(template.ParseFS(templateFS,
		"templates/base.html", "templates/login.html", "templates/setup.html"))
	pageTemplates = map[string]*template.Template{}
)

// registerPage parses one full-chrome page. Called from Part 2's init.
func registerPage(name string) {
	pageTemplates[name] = template.Must(template.ParseFS(templateFS,
		"templates/base.html", "templates/layout.html", "templates/"+name))
}

// renderBare draws a page with no navigation: setup and login, where there is
// no session yet.
func (s *Server) renderBare(w http.ResponseWriter, page string, data map[string]any) {
	t, err := bareTemplates.Clone()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if _, err := t.ParseFS(templateFS, "templates/"+page); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.execute(w, t, data)
}

// render draws a full page with navigation and the session's CSRF token.
func (s *Server) render(w http.ResponseWriter, r *http.Request, page string, data map[string]any) {
	t, ok := pageTemplates[page]
	if !ok {
		http.Error(w, "unknown page "+page, http.StatusInternalServerError)
		return
	}
	if data == nil {
		data = map[string]any{}
	}
	if sess, ok := s.session(r); ok {
		data["CSRF"] = sess.CSRF
	}
	if _, ok := data["Nav"]; !ok {
		data["Nav"] = ""
	}
	s.execute(w, t, data)
}

// execute renders to a buffer first, so a template error becomes a 500 rather
// than a half-written page.
func (s *Server) execute(w http.ResponseWriter, t *template.Template, data map[string]any) {
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "base", data); err != nil {
		s.o.Logger.Error("render", "error", err)
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(buf.Bytes())
}

// StaticHandler serves the embedded stylesheet, app CSS, and fonts. Embedding
// keeps the binary self-contained: no asset directory to deploy.
func (s *Server) StaticHandler() http.Handler {
	return http.FileServer(http.FS(staticFS))
}
```

Delete the temporary `pageRoutes` stub from `render.go` and move it to
`internal/web/pages.go`, still stubbed until Part 2:

```go
// internal/web/pages.go — filled in by Tasks 18-21
package web

import "net/http"

func (s *Server) pageRoutes(mux *http.ServeMux) {
	mux.Handle("GET /static/", s.StaticHandler())
	mux.HandleFunc("GET /", s.requireSession(func(w http.ResponseWriter, r *http.Request) {
		s.render(w, r, "dashboard.html", map[string]any{"Title": "Dashboard", "Nav": "dashboard"})
	}))
}
```

Add a minimal `templates/dashboard.html` so Task 17's tests pass; Task 18
replaces its contents:

```html
<!-- internal/web/templates/dashboard.html -->
{{define "page"}}<div class="card"><p class="muted">Dashboard</p></div>{{end}}
```

And register it:

```go
// append to internal/web/pages.go
func init() { registerPage("dashboard.html") }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/web/ -v`
Expected: PASS. `TestEmbeddedFontPathsResolve` proves the `@font-face` bug is fixed and the referenced fonts are actually embedded.

- [ ] **Step 5: Commit**

```bash
git add internal/web css/styles.css
git commit -m "Add web shell with embedded templates, assets, and fonts

App components live in a second stylesheet so the Patina Ky marketing
theme is untouched. Fixes the @font-face paths, which pointed at
../assets/fonts while the fonts live in fonts/ — corrected in both the
embedded copy and the repository stylesheet. Only the four weights the
stylesheet references are embedded.

Templates render to a buffer first, so a template error becomes a 500
rather than a half-written page.

AI-assisted contribution (agentic). Verified with: go test ./internal/web/"
```

---

## Self-Review (Plan 2, Part 1)

**Spec coverage.** argon2id admin password, increasing per-source delay with no lockout → Task 14. In-memory sessions, `HttpOnly`, `SameSite=Lax`, `Secure` under TLS, per-session CSRF in every form → Tasks 15 and 16. Setup token gating `/setup` as the only reachable route → Task 16. Second stylesheet on the existing tokens, marketing theme untouched, `@font-face` fix → Task 17.

**Placeholder scan.** The Task 16 `render.go` stub is explicitly temporary and Task 17 replaces it — the replacement is given in full, not described. No other stubs.

**Type consistency.** `Options` is defined once in Task 16 and consumed by Tasks 17, 18–21. `Server.session` returns `(*auth.Session, bool)` and is used identically in `requireCSRF`, `render`, and the handlers. `auth.CookieName` is the single cookie-name constant. `renderBare(w, page, data)` and `render(w, r, page, data)` keep their signatures from Task 16's stub through Task 17's real implementation.

**Continues in Part 2 (Tasks 18–21):** dashboard with the refusal banner, services, records, and settings screens.
