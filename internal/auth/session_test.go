package auth

import (
	"sync"
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
	// Get refreshes LastSeen, so another 50 minutes stays inside the window.
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

// An expired session must be dropped, not merely hidden.
func TestExpiredSessionIsEvicted(t *testing.T) {
	s := NewSessions(time.Minute, time.Hour)
	now := time.Now()
	s.now = func() time.Time { return now }
	sess := s.Create()
	now = now.Add(2 * time.Minute)
	s.Get(sess.ID)
	if s.Len() != 0 {
		t.Errorf("Len() = %d, want the expired session evicted", s.Len())
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
	if s.ValidCSRF(sess.ID, "") {
		t.Error("ValidCSRF() accepted an empty token")
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

func TestSessionsConcurrentUse(t *testing.T) {
	s := NewSessions(time.Hour, 12*time.Hour)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sess := s.Create()
			for j := 0; j < 50; j++ {
				if _, ok := s.Get(sess.ID); !ok {
					t.Error("session vanished under concurrent use")
					return
				}
				s.ValidCSRF(sess.ID, sess.CSRF)
			}
			s.Destroy(sess.ID)
		}()
	}
	wg.Wait()
	if s.Len() != 0 {
		t.Errorf("Len() = %d, want every session destroyed", s.Len())
	}
}
