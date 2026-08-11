// Package dhcp discovers names from DHCP leases. Leases are untrusted
// configuration input: everything here validates before publishing.
package dhcp

import (
	"context"
	"time"
)

// Lease is one DHCP lease. Hostname is already lowercased and validated.
type Lease struct {
	MAC      string
	IP       string
	Hostname string
	Expires  time.Time
}

// Source is one lease provider. dnsmasq is the reference implementation;
// ISC dhcpd and Kea slot in behind this interface without touching the poller.
type Source interface {
	Leases(ctx context.Context) ([]Lease, error)
	Name() string
}
