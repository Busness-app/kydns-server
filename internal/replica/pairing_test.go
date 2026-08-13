package replica

import (
	"testing"
	"time"
)

func TestPairingCodeIsUnguessable(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 500; i++ {
		c, err := NewPairingCode()
		if err != nil {
			t.Fatal(err)
		}
		if len(c) < 12 {
			t.Fatalf("code %q is %d characters; too short to resist "+
				"online guessing inside its ten-minute window", c, len(c))
		}
		if seen[c] {
			t.Fatalf("NewPairingCode() repeated %q within 500 draws", c)
		}
		seen[c] = true
	}
}

func TestInviteRedeemsOnce(t *testing.T) {
	now := time.Now()
	b := NewInviteBook(10*time.Minute, func() time.Time { return now })
	inv, err := b.Mint()
	if err != nil {
		t.Fatal(err)
	}
	if !b.Redeem(inv.Code) {
		t.Fatal("Redeem() rejected a fresh code")
	}
	if b.Redeem(inv.Code) {
		t.Fatal("Redeem() accepted a spent code; a captured code would pair a " +
			"second, unauthorized node")
	}
}

func TestInviteExpires(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	b := NewInviteBook(10*time.Minute, clock)
	inv, err := b.Mint()
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(11 * time.Minute)
	if b.Redeem(inv.Code) {
		t.Fatal("Redeem() accepted an expired code")
	}
}

func TestRedeemRejectsUnknownCode(t *testing.T) {
	b := NewInviteBook(10*time.Minute, time.Now)
	if b.Redeem("not-a-real-code") {
		t.Fatal("Redeem() accepted a code that was never minted")
	}
}
