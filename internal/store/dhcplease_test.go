package store

import "testing"

func TestDHCPLeaseRoundTrip(t *testing.T) {
	s := open(t)
	l := DHCPLease{MAC: "aa:bb:cc:dd:ee:ff", IP: "192.168.1.130", Hostname: "laptop", ExpiresAt: 2000, LastSeen: 1000}
	if err := s.PutDHCPLease(l); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := s.DHCPLeases()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 || got[0] != l {
		t.Fatalf("leases = %+v, want exactly %+v", got, l)
	}
}

func TestPutDHCPLeaseMovesAnAddressToANewMAC(t *testing.T) {
	s := open(t)
	old := DHCPLease{MAC: "aa:aa:aa:aa:aa:aa", IP: "192.168.1.130", Hostname: "old", ExpiresAt: 2000, LastSeen: 1000}
	if err := s.PutDHCPLease(old); err != nil {
		t.Fatalf("put old: %v", err)
	}
	// The IP column is UNIQUE. Re-issuing a released address to a different
	// client is normal, so this must succeed and evict the old row rather
	// than fail on the constraint.
	next := DHCPLease{MAC: "bb:bb:bb:bb:bb:bb", IP: "192.168.1.130", Hostname: "new", ExpiresAt: 3000, LastSeen: 2500}
	if err := s.PutDHCPLease(next); err != nil {
		t.Fatalf("put next: %v", err)
	}
	got, err := s.DHCPLeases()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 || got[0] != next {
		t.Fatalf("leases = %+v, want only %+v", got, next)
	}
}

func TestPutDHCPLeaseMovesAClientToANewAddress(t *testing.T) {
	s := open(t)
	mac := "aa:bb:cc:dd:ee:ff"
	if err := s.PutDHCPLease(DHCPLease{MAC: mac, IP: "192.168.1.130", Hostname: "laptop", ExpiresAt: 2000, LastSeen: 1000}); err != nil {
		t.Fatalf("put first: %v", err)
	}
	next := DHCPLease{MAC: mac, IP: "192.168.1.131", Hostname: "laptop", ExpiresAt: 3000, LastSeen: 2500}
	if err := s.PutDHCPLease(next); err != nil {
		t.Fatalf("put second: %v", err)
	}
	got, err := s.DHCPLeases()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 || got[0] != next {
		t.Fatalf("leases = %+v, want only %+v", got, next)
	}
}

func TestDeleteExpiredDHCPLeases(t *testing.T) {
	s := open(t)
	for _, l := range []DHCPLease{
		{MAC: "aa:aa:aa:aa:aa:aa", IP: "192.168.1.130", Hostname: "gone", ExpiresAt: 1000, LastSeen: 500},
		{MAC: "bb:bb:bb:bb:bb:bb", IP: "192.168.1.131", Hostname: "kept", ExpiresAt: 9000, LastSeen: 500},
	} {
		if err := s.PutDHCPLease(l); err != nil {
			t.Fatalf("put %s: %v", l.MAC, err)
		}
	}
	n, err := s.DeleteExpiredDHCPLeases(5000)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if n != 1 {
		t.Fatalf("pruned %d, want 1", n)
	}
	got, err := s.DHCPLeases()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 || got[0].Hostname != "kept" {
		t.Fatalf("leases = %+v, want only the unexpired one", got)
	}
}

func TestDeleteDHCPLease(t *testing.T) {
	s := open(t)
	mac := "aa:bb:cc:dd:ee:ff"
	if err := s.PutDHCPLease(DHCPLease{MAC: mac, IP: "192.168.1.130", Hostname: "laptop", ExpiresAt: 2000, LastSeen: 1000}); err != nil {
		t.Fatalf("put: %v", err)
	}
	if err := s.DeleteDHCPLease(mac); err != nil {
		t.Fatalf("delete: %v", err)
	}
	got, err := s.DHCPLeases()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("leases = %+v, want none", got)
	}
	// Releasing a lease that is already gone is normal: a client can send
	// RELEASE twice. It must not error.
	if err := s.DeleteDHCPLease(mac); err != nil {
		t.Fatalf("second delete: %v", err)
	}
}
