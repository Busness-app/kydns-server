package web

import (
	"testing"
	"time"
)

func TestShortDuration(t *testing.T) {
	for _, tc := range []struct {
		in   time.Duration
		want string
	}{
		{0, "0s"},
		{45 * time.Second, "45s"},
		{90 * time.Second, "1m"},
		{2 * time.Hour, "2h"},
		{26 * time.Hour, "1d 2h"},
	} {
		if got := shortDuration(tc.in); got != tc.want {
			t.Errorf("shortDuration(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// A server that has answered nothing must say so, not print a 1970 timestamp
// or "56 years ago" — that reads as a broken clock, not an idle server.
func TestSinceTextNeverIsNotAnEpochDate(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	if got := sinceText(0, now); got != "never" {
		t.Errorf("sinceText(0) = %q, want %q", got, "never")
	}
	if got := sinceText(now.Add(-90*time.Second).Unix(), now); got != "1m ago" {
		t.Errorf("sinceText(90s back) = %q, want %q", got, "1m ago")
	}
	if got := sinceText(now.Unix(), now); got != "just now" {
		t.Errorf("sinceText(now) = %q, want %q", got, "just now")
	}
}
